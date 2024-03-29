/* This is a Visual Studio Shared Project
 * This library requires .NET 4.7.2+ due to System.Text.Json instead of System.Web.Script.Serialization.JsonSerializer
 *
 * To use this project, add the project to your existing solution (Add->existing project->stashapi.shproj), then add a reference to the shared
 * project from your existing code/application project (Add->shared project reference->Shared Projects)
 * Structure:
 * - Solution
 * -- Code .net/c#/vb project
 * -- STASHAPI shared project
 * 
 * Important Note - you must add the following references to you code/application project
 * You must also add the Newtonsoft.JSON nuget package (handles all serialize operations; will eventually handle all serialize/deserialize operations)
 */
using System;                           // Reference: System
using System.Text;                      // Reference: System
using System.Text.Json;                 // Reference: System
using System.Text.RegularExpressions;   // Reference: System
using System.Security.Cryptography;     // Reference: System
using System.Net;                       // Reference: System
using System.Web;                       // Reference: System.Web 
using System.Collections.Generic;       // Reference: System
using System.Globalization;             // Reference: System
using System.Threading;                 // Reference: System
using System.Threading.Tasks;           // Reference: System
using System.IO;                        // Reference: System
using System.Net.Http;                  // Reference: System.Net.Http
using System.Linq;                      // Reference: System
using System.Diagnostics;

namespace Stash
{
    public class StashAPI : Object
    {
        public const string FILE_VERSION = "1.0.8";
        public const string STASHAPI_VERSION = "1.0";       // API Version
        public const int STASHAPI_ID_LENGTH = 32;        // api_id String length
        public const int STASHAPI_PW_LENGTH = 32;        // API_PW String length (minimum)
        public const int STASHAPI_SIG_LENGTH = 32;       // API_SIGNATURE String length (minimum)
        public const int STASHAPI_FILE_BUFFER_SIZE = 65536;        // 65k, Input / Output buffer for reading / writing files
        public const int STASHAPI_LARGEFILE_SIZE = 10485760;       // 10MB, Files larger than this value will use the STASHAPI_LARGEFILE_BUFFER_SIZE for transfers
        public const int STASHAPI_LARGEFILE_BUFFER_SIZE = 524288;  // 512k, Files larger than LARGEFILE_SIZE use this buffer size
        public const int STASHAPI_XLARGEFILE_SIZE = 1073741824;         // 1GB, Files larger than this value will use the STASHAPI_XLARGEFILE_BUFFER_SIZE for transfer
        public const int STASHAPI_XLARGEFILE_BUFFER_SIZE = 10485760;    // 10MB, Files larger than XLARGEFILE_SIZE will use this buffer size
        public const string BASE_VAULT_FOLDER = "My Home";
        public const string BASE_URL = "https://www.stage.stashbusiness.com/";      // This is the URL to send requests to, can be overrided by BASE_API_URL in the constructor
        public const string ENC_ALG = "aes-256-cbc";        // Encryption algorithm for use in encryptString & decryptString(), encryptFile() & decryptFile(), uses an IV of 16 bytes
        //public const int STASH_ENC_BLOCKSIZE = 1024;        // The size of the data block to encrypt; must match the blocksize used in the decryption platform - IV.length
        //public const int STASH_DEC_BLOCKSIZE = 1040;        // The size of the data block to decrypt; must be STASH_ENC_BLOCKSIZE + IV.length; must match the blocksize used in the encryption platform + IV.length
        public const int STASH_ENC_BLOCKSIZE = 32768;        // The size of the data block to encrypt; must match the blocksize used in the decryption platform - IV.length
        public const int STASH_DEC_BLOCKSIZE = 32784;        // The size of the data block to decrypt; must be STASH_ENC_BLOCKSIZE + IV.length; must match the blocksize used in the encryption platform + IV.length

        private static HttpClient client;

        private string _api_id;             // The API_ID For your account
        public string api_id
        {
            get
            { return this._api_id; }
            set
            {
                if (this.verbosity) Console.WriteLine(" - setId - " + value);
                Dictionary<string, object> tDict = new Dictionary<string, object>();
                tDict.Add("api_id", value);
                if (!this.isValid(tDict))
                {
                    throw new Exception("Invalid API ID");
                }
                else
                {
                    this._api_id = value;
                }
            }
        }

        private string _api_pw;       // The API_PW for your account
        public string api_pw
        {
            get
            {
                return this._api_pw;
            }
            set
            {
                if (this.verbosity) Console.WriteLine(" - setPw - " + value);
                Dictionary<string, object> tDict = new Dictionary<string, object>();
                tDict.Add("api_pw", value);
                if (!this.isValid(tDict))
                {
                    throw new Exception("Invalid API PW");
                }
                else
                {
                    this._api_pw = value;
                }
            }
        }

        public string api_signature;           // The sha256 hmac signature For the request, has non property based set and get functions
        public string api_version;             // The API version which generated the request, has non property based get function, set done in constructor
        private int _api_timestamp;             // The timestamp For When the request was generated
        public int api_timestamp
        {
            get
            {
                return this._api_timestamp;
            }
            set
            {
                int uTime = 0;
                if (value <= 0)
                {
                    uTime = Convert.ToInt32((DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds);
                }
                else
                {
                    uTime = value;
                }
                if (this.verbosity) Console.WriteLine(" - setTimestamp - " + uTime);
                Dictionary<string, object> tDict = new Dictionary<string, object>();
                tDict.Add("api_timestamp", uTime);
                if (!this.isValid(tDict))
                {
                    throw new Exception("Invalid API Timestamp");
                }
                else
                {
                    this._api_timestamp = uTime;
                }
            }
        }
        private bool verbosity = false;
        public string url = "";                         // The URL to send the request to
        public Dictionary<string, object> dParams;               // Associative array of parameters to send with the request
        public string BASE_API_URL = "";           // The BASE URL to use for the request
        public string apiSubsystem = "";
        public string apiOperation = "";
        public List<string> NoIdOperations = new List<string>{"getapicreds", "getsecret"};  // These requests don't need an API_ID

        /// <summary>
        /// STASHAPI.CS Constructor
        /// NOTE - this object does NOT appear to be thread safe for file uploads - create a new object for uploading each time
        /// </summary>
        /// <param name="apiId"></param>
        /// <param name="apiPw"></param>
        /// <param name="urlIn"></param>
        /// <param name="verbosity"></param>
        public StashAPI(string apiId = "", string apiPw = "", string urlIn = "", bool verbosity = false)
        {
            this.api_version = STASHAPI_VERSION;
            this.verbosity = verbosity;
            if (apiId != "")
            {
                this.api_id = apiId;
            }
            if (apiPw != "")
            {
                this.api_pw = apiPw;
            }
            this.BASE_API_URL = (urlIn != "" && urlIn != null ? urlIn : BASE_URL);
            if (!this.BASE_API_URL.EndsWith("/"))
            {
                this.BASE_API_URL += "/";
            }            
        }

        public bool getVerbosity()
        {
            return this.verbosity;
        }

        // Returns the constants used in the API Class
        public string[] getConstants()
        {
            string[] retArray = new string[] { "Not Implemented" };
            return retArray;
        }

        // Returns a string representation of this object
        public override string ToString()
        {
            return "STASHAPI Object - Version: " + this.api_version + " ID: " + this.api_id;
        }

        // Returns the version for this API
        public string getVersion()
        {
            return this.api_version;
        }

        // ' Signs the request with the current data in the STASHAPI request instance
        public bool setSignature(Dictionary<string, object> dataIn)
        {
            string sig = "";
            string strToSign = "";

            if (this.verbosity) Console.WriteLine(" - setSignature - dataIn: " + DictToString(dataIn));
            if (!dataIn.TryGetValue("url", out object url) || url == null || url.ToString() == "") { throw new System.Exception("Input array missing url for signature calculation"); }
            if (!dataIn.TryGetValue("api_version", out object apiVersion) || apiVersion == null || apiVersion.ToString() == "") { throw new System.Exception("Input array missing api_version for signature calculation"); }
            if (!dataIn.TryGetValue("api_id", out object apiId) || apiId == null || apiId.ToString() == "") { throw new System.Exception("Input array missing api_id for signature calculation"); }
            if (!dataIn.TryGetValue("api_timestamp", out object apiTimestamp) || apiTimestamp == null || apiTimestamp.ToString() == "") { throw new System.Exception("Input array missing api_timestamp for signature calculation"); }
            if (dataIn.ContainsKey("api_signature")) { dataIn.Remove("api_signature"); }

            // Any unicode characters in dataIn when it's encoded by json_encode will get lowercase codes e.g. \u00d
            // but in JsonSerializer, it will get uppercase codes, e.g. \u00D
            // See https://stackoverflow.com/questions/69675115/httpclient-and-system-text-json-jsonserializer-and-php-different-character-size?noredirect=1#comment123168070_69675115
            // The Newtonsoft.Json library is used to create an exact-case match with PHP's json_encode function
            strToSign = Newtonsoft.Json.JsonConvert.SerializeObject(dataIn);

            sig = Hash_hmac("sha256", strToSign, this.api_pw);

            // Convert to lowercase to match PHP's hash_hmac function which outputs lowercase hexbits
            this.api_signature = sig.ToLower();
            if (this.verbosity) { Console.WriteLine(" - setSignature - strToSign: " + strToSign + " sig: " + this.api_signature); }
            return true;
        }

        // Gets the currently set signature value
        public string getSignature()
        {
            return this.api_signature;
        }

        // Encrypts a file with AES-256-CBC; encrypts a file in individual blocks
        // Cross-platform compatible; must use same (DEC_BLOCKSIZE - IV.Length) as the platform used for decryption
        public bool EncryptFileChunked(string fileName, out string encFileName, out string errMsg)
        {
            errMsg = "";
            encFileName = fileName + ".enc";
            byte[] pt;
            byte[] ct;

            if (!File.Exists(fileName)) { throw new ArgumentException("Input File Does Not Exist"); }

            using (BinaryWriter wrt = new BinaryWriter(new FileStream(encFileName, FileMode.Create, FileAccess.Write, FileShare.Read)))
            using (BinaryReader rdr = new BinaryReader(File.OpenRead(fileName)))
            {
                long fileLen = rdr.BaseStream.Length;
                long counter = 0;
                while (counter < fileLen)
                {
                    if (fileLen - counter > STASH_ENC_BLOCKSIZE)
                    {
                        // First + following blocks up to but not including last block of file unless its an even blocksize
                        pt = new byte[STASH_ENC_BLOCKSIZE];
                        pt = rdr.ReadBytes(STASH_ENC_BLOCKSIZE);
                        counter += STASH_ENC_BLOCKSIZE;
                    }
                    else
                    {
                        // Last block
                        pt = new byte[fileLen - counter];
                        pt = rdr.ReadBytes((int)(fileLen - counter));
                        counter = fileLen;
                    }

                    ct = EncryptString(pt, "");
                    wrt.Write(ct);
                }
            }
            return true;
        }

        // Encrypts a String with keyIn, or if empty, the API_PW
        public string EncryptString(string strString, string keyIn, bool returnHexBits)
        {
            string retVal = "";
            byte[] tRetVal;

            // If both keyIn and api_pw are empty/null, return empty string - this usually occurs during getApiCreds
            // where the keyIn hasn't been calculated yet and the api_pw is not required
            if (keyIn == "" && (this.api_pw == null || this.api_pw == ""))
            {
                return "";
            }

            if (strString == "") { return ""; }
            if (this.api_pw == "" && keyIn == "") { return ""; }
            if (this.api_pw.Length != 32 && keyIn == "") { throw new ArgumentException("API_PW must be 32 characters in length"); }
            if (this.api_pw == "" && keyIn.Length != 32) { throw new ArgumentException("keyIn must be 32 characters in length"); }

            Aes crypto = Aes.Create();
            if (keyIn != "")
            {
                crypto.Key = Encoding.ASCII.GetBytes(keyIn);
            }
            else
            {
                crypto.Key = Encoding.ASCII.GetBytes(this.api_pw);
            }
            crypto.Mode = CipherMode.CBC;
            crypto.Padding = PaddingMode.PKCS7;
            
            ICryptoTransform encryptor = crypto.CreateEncryptor(crypto.Key, crypto.IV);
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(strString);
                    }
                    tRetVal = msEncrypt.ToArray();
                }
            }

            // Build IV portion of return value
            int counter = 0;
            for (int i = 0; i <= crypto.IV.Length - 1; i++)
            {
                counter++;
                if (returnHexBits)
                {
                    retVal = retVal + crypto.IV[i].ToString("X2");
                }
                else
                {
                    retVal = retVal + crypto.IV[i].ToString();
                }
            }

            // Build ct portion of the return value
            counter = 0;
            for (int i = 0; i <= tRetVal.Length - 1; i++)
            {
                counter++;
                if (returnHexBits)
                {
                    retVal = retVal + Convert.ToInt32(tRetVal[i]).ToString("X2");
                }
                else
                {
                    retVal = retVal + tRetVal[i].ToString();
                }
            }

            // Change all codes to lowercase, to match PHP's bin2hex function
            if (returnHexBits)
            {
                Regex reg = new Regex("[A-F]");
                retVal = reg.Replace(retVal, new MatchEvaluator(regexToLower));
            }
            return retVal;
        }

        // Encrypts a set of bytes with keyIn, or if empty, the API_PW
        // Returns the encrypted string, or byte array with single entry set to 0
        public byte[] EncryptString(byte[] strString, string keyIn)
        {
            byte[] retVal;
            byte[] ct;

            // If both keyIn and api_pw are empty/null, return empty string - this usually occurs during getApiCreds
            // where the keyIn hasn't been calculated yet and the api_pw is not required
            if (keyIn == "" && (this.api_pw == null || this.api_pw == ""))
            {
                return new byte[0];
            }

            if (strString.Length < 1) { throw new ArgumentException("Input Bytes are Empty"); }
            if (this.api_pw == "" && keyIn == "") { return null; }
            if (this.api_pw.Length != 32 && keyIn == "") { throw new ArgumentException("API_PW must be 32 characters in length"); }//if (this.api_pw.Length < 32) { throw new ArgumentException("API_PW must be at least 32 characters"); }
            if (this.api_pw == "" && keyIn.Length != 32) { throw new ArgumentException("keyIn must be 32 characters in length"); }

            Aes crypto = Aes.Create();
            if (keyIn != "")
            {
                crypto.Key = Encoding.ASCII.GetBytes(keyIn);
            }
            else
            {
                crypto.Key = Encoding.ASCII.GetBytes(this.api_pw);
            }
            crypto.Mode = CipherMode.CBC;
            crypto.Padding = PaddingMode.PKCS7;

            ICryptoTransform encryptor = crypto.CreateEncryptor(crypto.Key, crypto.IV);
            using (MemoryStream msEncrypt = new MemoryStream(strString))
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Read))
            using (BinaryReader srEncrypt = new BinaryReader(csEncrypt))
            {
                //ct = srEncrypt.ReadBytes(1024);
                ct = srEncrypt.ReadBytes(STASH_ENC_BLOCKSIZE);
            }

            retVal = new byte[ct.Length + crypto.IV.Length];
            Buffer.BlockCopy(crypto.IV, 0, retVal, 0, crypto.IV.Length);
            Buffer.BlockCopy(ct, 0, retVal, crypto.IV.Length, ct.Length);

            return retVal;
        }

        // Decrypts a File with the API_PW
        // Buffer Block size must match StashEncryption.php::STASH_DEC_BLOCKSIZE to be cross-platform compatible
        public bool DecryptFileChunked(string fileName, out string decFileName, out string errMsg)
        {
            //const int STASH_DEC_BLOCKSIZE = 1040;
            decFileName = fileName + ".dec";
            errMsg = "";
            byte[] strIv;                                       // The Init Vector
            long fileLen = 0;                                   // Stores the file length of the CT file
            byte[] ct;                                          // Working buffer for converting CT to PT
            byte[] pt;                                          // Working output buffer containing the PT
            Aes crypto;
            try
            {
                crypto = Aes.Create();
                strIv = new byte[crypto.IV.Length];          // Build the init vector byte array

                // Get IV from file
                using (BinaryReader rdr = new BinaryReader(File.OpenRead(fileName)))
                {
                    // Read IV length bytes out
                    strIv = rdr.ReadBytes(crypto.IV.Length);
                    fileLen = rdr.BaseStream.Length;
                }

                crypto.Mode = CipherMode.CBC;
                crypto.Key = Encoding.ASCII.GetBytes(this.api_pw);
                crypto.IV = strIv;
                crypto.Padding = PaddingMode.PKCS7;

                // Read CT from file and decrypt it, and write it out
                long offset = strIv.Length;
                using (BinaryWriter wrt = new BinaryWriter(File.OpenWrite(decFileName)))
                using (BinaryReader rdr = new BinaryReader(File.OpenRead(fileName)))
                using (ICryptoTransform decryptor = crypto.CreateDecryptor(crypto.Key, crypto.IV))
                {
                    rdr.BaseStream.Seek(offset, SeekOrigin.Begin);
                    // Need loop here to read entire file in blocks
                    while (offset < fileLen)
                    {
                        if (fileLen - offset > STASH_DEC_BLOCKSIZE)
                        {
                            ct = new byte[STASH_DEC_BLOCKSIZE];
                            ct = rdr.ReadBytes(STASH_DEC_BLOCKSIZE);
                            offset += STASH_DEC_BLOCKSIZE;
                        }
                        else
                        {
                            ct = new byte[fileLen - offset];
                            ct = rdr.ReadBytes((int)(fileLen - offset));
                            offset = fileLen;
                        }

                        using (MemoryStream msDecrypt = new MemoryStream(ct))
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        using (BinaryReader srDecrypt = new BinaryReader(csDecrypt))
                        {
                            pt = srDecrypt.ReadBytes(STASH_DEC_BLOCKSIZE);
                            wrt.Write(pt);
                        }
                    }

                    return true;
                }
            }
            catch (Exception e)
            {
                errMsg = e.Message;
                return false;
            }
        }

        // Decrypts a String with the API_PW
        public string DecryptString(string strString, bool inHexBits)
        {
            object tRetVal;

            if (strString == "") { return ""; }
            if (this.api_pw == "") { return ""; }
            if (this.api_pw.Length < 32) { throw new ArgumentException("API_PW must be at least 32 characters"); }

            if (inHexBits)
            {
                strString = hex2bin(strString);
            }

            // Convert input string to a byte array to create IV and CT arrays
            // Assume input array after hex2bin has null padding elements between chars in the array, e.g. 41-0-38-0-133-0-208...
            byte[] strBytesUni = Encoding.Unicode.GetBytes(strString);
            byte[] strBytes = new byte[strBytesUni.Length / 2];
            int counter = 0;
            for (int i = 0; i < strBytesUni.Length; i++)
            {
                if (strBytesUni[i] != 0)
                {
                    strBytes[counter] = strBytesUni[i];
                    counter++;
                }
            }

            Aes crypto = Aes.Create();

            byte[] strIv = new byte[crypto.IV.Length];         // Build the init vector byte array
            for (int i = 0; i < crypto.IV.Length; i++)
            {
                strIv[i] = strBytes[i];
            }

            byte[] strCt = new byte[strString.Length - crypto.IV.Length];     // Build the ciphertext byte array
            counter = 0;
            for (int i = crypto.IV.Length; i < strString.Length; i++)
            {
                strCt[counter] = strBytes[i];
                counter++;
            }

            crypto.Mode = CipherMode.CBC;
            crypto.Key = Encoding.ASCII.GetBytes(this.api_pw);
            crypto.IV = strIv;
            crypto.Padding = PaddingMode.PKCS7;

            if (strString.Length < crypto.IV.Length) { throw new Exception("Insufficient Input Data to Decrypt"); }

            ICryptoTransform decryptor = crypto.CreateDecryptor(crypto.Key, crypto.IV);
            MemoryStream msDecrypt = new MemoryStream(strCt);
            CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            StreamReader srDecrypt = new StreamReader(csDecrypt);
            tRetVal = srDecrypt.ReadToEnd();

            return tRetVal.ToString();
        }

        // Checks the parameter and value for sanity and compliance with rules
        public bool isValid(Dictionary<string, object> arrDataIn)
        {
            bool retVal = false;
            try
            {
                foreach (KeyValuePair<string, object> kvp in arrDataIn)
                {
                    string idx = kvp.Key;
                    string val = kvp.Value.ToString();

                    if (idx == "api_id")                // API_ID Is 32 chars, a-f,0-9 (hex chars only), OR a user email address (for AD environments)
                    {
                        // Check if api_id is a valid email address, otherwise, assume its a 32 char traditional id
                        if (!IsValidEmail(val))
                        {
                            if (val.Length != STASHAPI_ID_LENGTH)
                            {
                                throw new Exception(idx + " Must Be " + STASHAPI_ID_LENGTH + " Characters in Length");
                            }
                            if (Regex.Match(val, "[^abcdef0-9]", RegexOptions.IgnoreCase).Success)
                            {
                                throw new Exception(idx + " Has Invalid Characters, only a-f and 0-9 are allowed");
                            }
                        }
                    }
                    else if (idx == "api_pw")           // API_PW is a-z, A-Z, and 0-9 characters only
                    {
                        if (val.Length < STASHAPI_PW_LENGTH)
                        {
                            throw new Exception(idx + " Must Be at Least " + STASHAPI_PW_LENGTH + " Characters in Length");
                        }
                        if (Regex.Match(val, "[^a-zA-Z0-9]", RegexOptions.IgnoreCase).Success)
                        {
                            throw new Exception(idx + " Has Invalid Characters, only A-Z, a-z and 0-9 are allowed");
                        }
                    }
                    else if (idx == "api_signature")
                    {
                        if (val.Length < STASHAPI_SIG_LENGTH)
                        {
                            throw new Exception(idx + " Must Be at Least " + STASHAPI_SIG_LENGTH + " Characters in Length");
                        }
                        if (Regex.Match(val, "[^abcdef0-9]", RegexOptions.IgnoreCase).Success)
                        {
                            throw new Exception(idx + " Has Invalid Characters, only a-f and 0-9 are allowed");
                        }
                    }
                    else if (idx == "api_timestamp")
                    {
                        if (Convert.ToInt32(val) <= 0)
                        {
                            throw new Exception(idx + " Must be an Integer Value and Greater Than 0");
                        }
                    }
                    else if (idx == "api_version")
                    {
                        if (val != this.api_version)
                        {
                            throw new Exception(idx + " Does Not Match API Version for this Code");
                        }
                    }
                    else if (idx == "verbosity")
                    {
                        // Not needed, the explicit conversion to boolean will strip anything out
                    }
                    else if (idx == "url")
                    {
                        if (!IsValidURL(val))
                        {
                            throw new Exception(idx + " Must be a Valid URL - including https");
                        }
                    }
                    else if (idx == "params")
                    {
                        // Do nothing, skip params element
                    }
                }
                retVal = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Invalid Parameter - " + ex.Message);
                retVal = false;
            }
            return retVal;
        }

        /*
         * Posts a string of JSON (payload) to the specified URI and returns the string response
         * See https://carldesouza.com/httpclient-getasync-postasync-sendasync-c/
        */
        public async Task<string> PostURI(string uri, string payload)
        {
            client = new HttpClient();
            HttpResponseMessage response = await client.PostAsync(uri, new StringContent(payload, Encoding.UTF8, "application/json"));
            return await response.Content.ReadAsStringAsync();
        }

        /*
         * Posts a string of JSON (payload) to the specified URI and returns a stream for the response (e.g. when downloading a file)
         * See https://www.tugberkugurlu.com/archive/efficiently-streaming-large-http-responses-with-httpclient
         */
        public async Task<Stream> PostURIasStream(string uri, string payload, double timeOutIn, CancellationToken ct)
        {
            // ToDo - fix to get over 2GB response buffer limit?
            //aronccs Create a HttpRequestMessage, set the method to POST and pass it to SendAsync with the appropriate HttpCompletionOption
            // See https://stackoverflow.com/questions/18720435/httpclient-buffer-size-limit-exceeded
            client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(timeOutIn);
            HttpRequestMessage hrm = new HttpRequestMessage(HttpMethod.Post, uri);
            hrm.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            HttpResponseMessage response = await client.SendAsync(hrm, HttpCompletionOption.ResponseHeadersRead, ct);
            //HttpResponseMessage response = await client.PostAsync(uri, new StringContent(payload, Encoding.UTF8, "application/json"), ct);
            return response.Content.ReadAsStream(ct);
        }

        // Sends a generic request to the API
        public string SendRequest()
        {
            string retVal = "";
            string payload = "";

            if (this.verbosity) { Console.WriteLine(" - sendRequest - "); }
            if (this.url == "") { throw new ArgumentException("Invalid URL"); }

            //System.Net.HttpWebRequest objHWR = (HttpWebRequest)WebRequest.Create(this.url);

            Dictionary<string, object> apiParams = new Dictionary<string, object>();
            apiParams.Add("url", this.url);
            apiParams.Add("api_version", this.api_version);
            apiParams.Add("api_id", this.api_id);
            this.api_timestamp = 0;                // Set to current timestamp
            apiParams.Add("api_timestamp", this.api_timestamp);

            // Sign Request
            if ((this.dParams != null) && this.dParams.Count > 0)
            {
                this.setSignature(Dictionaries_merge(apiParams, this.dParams));
            }
            else
            {
                this.setSignature(apiParams);
            }
            apiParams.Add("api_signature", this.getSignature());

            // Build payload
            //payload = JsonSerializer.Serialize(apiParams);       // apiParams is already merged if need be in signature above
            //byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
            payload = Newtonsoft.Json.JsonConvert.SerializeObject(apiParams);

            //objHWR.Method = WebRequestMethods.Http.Post;
            //objHWR.ContentType = "application/json";
            //objHWR.ContentLength = payloadBytes.Length;

            //System.IO.Stream sendStream = objHWR.GetRequestStream();
            //sendStream.Write(payloadBytes, 0, payloadBytes.Length);
            //sendStream.Close();

            //WebResponse objResponse = objHWR.GetResponse();
            //sendStream = objResponse.GetResponseStream();
            //System.IO.StreamReader reader = new System.IO.StreamReader(sendStream);
            //retVal = reader.ReadToEnd();
            //reader.Close();
            //sendStream.Close();
            //objResponse.Close();

            var t = Task.Run(() => PostURI(this.url, payload));
            t.Wait();
            retVal = t.Result;
            //Console.WriteLine("Result: " + t.Result);   

            if (this.verbosity) { Console.WriteLine("- sendRequest Complete - Result: " + retVal); }
            return retVal;
        }

        // Downloads a file from the Vault and stores it in _fileNameIn_

        /// <summary>
        /// Downloads a file from the Vault and stores it in a local file specified by fileNameIn
        /// </summary>
        /// <param name="fileNameIn">string, the full path and name of file to download content to</param>
        /// <param name="fileSize">ulong, the size of the file</param>
        /// <param name="timeOut">int, the timeout (in seconds) for the transfer settings</param>
        /// <param name="callback">Action<ulong, ulong, string>, a callback function to update status</param>
        /// <param name="cts">CancellationTokenSource, used to indicate if the download should be cancelled</param>
        /// <param name="retCode">int, output - the return code (e.g. 200, 404, etc)</param>
        /// <returns>string, "1" for success, otherwise an error message</returns>
        /// <exception cref="ArgumentException">thrown for errors with the URL</exception>
        public string sendDownloadRequest(string fileNameIn, ulong fileSize, int timeOut, Action<ulong, ulong, string> callback, CancellationTokenSource cts, out int retCode)
        {
            string payload = ""; 
            retCode = 0;

            if (this.verbosity) { Console.WriteLine(" - sendDownloadRequest - "); }
            if (this.url == "") { throw new ArgumentException("Invalid URL"); }
            FileStream fileStream = null;
            Stream sendStream = null;

            try
            {
                Dictionary<string, object> apiParams = new Dictionary<string, object>();
                apiParams.Add("url", this.url);
                apiParams.Add("api_version", this.api_version);
                apiParams.Add("api_id", this.api_id);
                this.api_timestamp = 0;        // Set to current timestamp
                apiParams.Add("api_timestamp", this.api_timestamp);

                // Sign Request
                if ((this.dParams != null) && this.dParams.Count > 0)
                {
                    this.setSignature(Dictionaries_merge(apiParams, this.dParams));
                }
                else
                {
                    this.setSignature(apiParams);
                }
                apiParams.Add("api_signature", this.getSignature());

                // Build payload
                payload = Newtonsoft.Json.JsonConvert.SerializeObject(apiParams);       // apiParams is already merged if need be in signature above
                //payload = JsonSerializer.Serialize(apiParams);       // apiParams is already merged if need be in signature above
                //byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
                
                var t = Task.Run(() => PostURIasStream(this.url, payload, timeOut, cts.Token));
                t.Wait();
                if (cts.IsCancellationRequested) { throw new OperationCanceledException("Client Cancelled Download");  }

                sendStream = t.Result;                

                int bufferSize = STASHAPI_FILE_BUFFER_SIZE;
                if (fileSize >= STASHAPI_XLARGEFILE_SIZE)
                {
                    bufferSize = STASHAPI_XLARGEFILE_BUFFER_SIZE;
                } else if (fileSize >= STASHAPI_LARGEFILE_SIZE)
                {
                    bufferSize = STASHAPI_LARGEFILE_SIZE;
                }

                byte[] buffer = new byte[bufferSize];
                int bytesRead = sendStream.Read(buffer, 0, buffer.Length);
                ulong totalBytesRead = Convert.ToUInt64(bytesRead);
                ulong totalBytes = fileSize;

                // Examine buffer for error JSON and if found, skip the download and return error
                // If any error occurs during this error check, just dump the output to the file anyway
                try
                {
                    string tStr = Encoding.ASCII.GetString(buffer, 0, 1000);

                    int idx = tStr.IndexOf('\0');
                    if (idx >= 1)
                    {
                        tStr = tStr.Substring(0, idx);
                        apiError apiErr = JsonSerializer.Deserialize<apiError>(tStr);
                        if (apiErr.code >= 400 && apiErr.code <= 500)
                        {   // The value returned was an API error JSON string, not the file content, return the error JSON
                            retCode = apiErr.code;
                            return tStr;
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Do nothing, assume the error check failed and its a valid file
                    string msg = ex.Message;
                }
                
                fileStream = new System.IO.FileStream(fileNameIn, System.IO.FileMode.Create, System.IO.FileAccess.Write);
                while (bytesRead != 0)
                {
                    if (cts != null && cts.IsCancellationRequested)
                    {
                        throw new OperationCanceledException("Client Cancelled Download");
                    }

                    fileStream.Write(buffer, 0, bytesRead);
                    bytesRead = sendStream.Read(buffer, 0, buffer.Length);
                    totalBytesRead += Convert.ToUInt64(bytesRead);

                    callback?.Invoke(totalBytes, totalBytesRead, fileNameIn);       // Trigger callback if defined
                }
                retCode = 200;
                return "1";
            }
            catch (Exception ex)
            {
                if (ex is OperationCanceledException || ex is TaskCanceledException || ex.InnerException.Message == "A task was canceled.")
                {
                    retCode = 499;
                    return ex.Message;
                }
                else
                {
                    retCode = 500;
                    return ex.Message;
                }
            }
            finally
            {
                if (fileStream != null) { fileStream.Close(); }
                if (sendStream != null) { sendStream.Close(); }
            }
        }

        // Uploads a file to the server with a set timeOut
        public string SendFileRequest(string fileNameIn, int timeOut)
        {
            string retVal = "";

            long fileSize = new FileInfo(fileNameIn).Length;

            // Placeholder / empty callback - this is empty because this is intended for single, small file uploads, anything else should use SendFileRequestChunked / PutFileChunked
            Action<ulong, ulong, string> callback = (fileSize, processedBytes, name) =>
            {
                // nothing
            };

            string resumeToken = "";            // Ignored in SendFileRequest()/ putFile() - only used in putFileChunked()
            var t = Task.Run(() => this.SendFileRequestChunked(fileNameIn, Convert.ToInt32(fileSize), timeOut, callback, new CancellationTokenSource(), resumeToken, false));
            t.Wait();
            retVal = t.Result;

            if (this.verbosity)
            {
                Console.WriteLine("- sendFileRequest Complete - Result: " + retVal);
            }

            return retVal;            
        }

        // Uploads a file to the server in chunks. While the functions are awaited, the chunks are being uploaded to the file synchronously.
        public async Task<string> SendFileRequestChunked(string fileNameIn, int chunkSize, int timeOutSeconds, Action<ulong, ulong, string> callback, System.Threading.CancellationTokenSource cts, string resumeToken, bool resumeUpload)
        {
            string retVal = "";

            if (this.verbosity) { Console.WriteLine(" - sendFileRequest - "); }
            if (this.url == "") { throw new ArgumentException("Invalid URL"); }
            if (fileNameIn == "" || !System.IO.File.Exists(fileNameIn)) { throw new ArgumentException("A Filename Must Be Specified, or File Does Not Exist"); }
            string guidFile = "STASHFILE_" + System.Guid.NewGuid().ToString();

            FileStream fileStream = null;
            try
            {
                int i = 1;

                fileStream = new FileStream(fileNameIn, FileMode.Open, FileAccess.Read,
                FileShare.Read, bufferSize: chunkSize, useAsync: true);
                bool fileDone = false;          // Flag to track if file is being resumed from the point its been completely uploaded already (e.g. there was an error with encrypt, slice or sending to storage)

                // If resumeUpload flag set, resumeToken set, and able to seek on the FileStream - try a resume
                if (resumeUpload && resumeToken != "" && fileStream.CanSeek)
                {
                    // Copy the dParams dictionary so it can be reused after GetResumeIndex clears this.dParams
                    //Dictionary<string, object> tDict = this.convertDestinationToSourceDictionary(this.dParams, true);
                    Dictionary<string, object> tDict = this.CopyDictionary(this.dParams);

                    // Get length of file with resumeToken name on server - this will be the position to start from
                    string apiResponseString = this.GetResumeIndex(new Dictionary<string, object>()
                    {
                        { "resumetoken", resumeToken}
                    }, out int retCode, out ulong resumeIndex);

                    if (resumeIndex > 0)
                    {
                        try
                        {
                            fileStream.Seek(Convert.ToInt64(resumeIndex), SeekOrigin.Begin);
                            i = (int)(resumeIndex / Convert.ToUInt64(chunkSize)) + 1;
                            if (Convert.ToUInt64(fileStream.Length) == resumeIndex) { fileDone = true; }
                        } catch (Exception)
                        {
                            // Something failed with seek - reset it to 0 and start upload over again
                            fileStream.Seek(0, SeekOrigin.Begin);
                            resumeIndex = 0;
                            resumeUpload = false;
                        }
                    }
                    this.dParams = tDict;
                }

                // Do not need to set URL because this is a base call, Support File writes, File Writes, and Chunked File Writes will all set the URL before calling this function

                // Build params list containing needed API fields
                System.IO.FileInfo uploadFile = new System.IO.FileInfo(fileNameIn);
                Dictionary<string, string> chunkedParams = new Dictionary<string, string>();

                chunkedParams.Add("temp_name", resumeToken);

                if (uploadFile.Length <= chunkSize)
                {
                    chunkSize = Convert.ToInt32(uploadFile.Length);  // if the file is smaller than the chunk size, upload the file as one chunk
                }

                byte[] buffer = new byte[chunkSize];

                Int32 bytesRead = 0;
                var responseString = string.Empty;

                Dictionary<string, object> apiParams = new Dictionary<string, object>();
                apiParams.Add("url", this.url);
                apiParams.Add("api_version", this.api_version);
                apiParams.Add("api_id", this.api_id);
                this.api_timestamp = 0;        // Set to current timestamp
                apiParams.Add("api_timestamp", this.api_timestamp);
                apiParams.Add("file_guid", guidFile);
                // Sign Request
                if ((this.dParams != null) && this.dParams.Count > 0)
                {
                    this.setSignature(Dictionaries_merge(apiParams, this.dParams));
                }
                else
                {
                    this.setSignature(apiParams);
                }
                apiParams.Add("api_signature", this.getSignature());

                //Begin reading the file and send each chunk to the server.
                while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0 || fileDone)
                {
                    //Check cancellation token. If the user clicks stop, the upload will be aborted.
                    if (cts != null && cts.IsCancellationRequested)
                    {
                        throw new OperationCanceledException("Client Cancelled Upload");
                    }
                    else
                    {
                        double chunks = (double)fileStream.Length / (double)chunkSize;
                        var totalChunks = Math.Ceiling(chunks);

                        //if (i == 3)
                        //{
                        //    stopWatch.Stop();
                        //    TimeSpan ts = stopWatch.Elapsed;
                        //}
                        if (chunkedParams.ContainsKey("progress"))
                        {
                            chunkedParams.Remove("progress");
                        }

                        if (!chunkedParams.ContainsKey("chunkedUpload"))
                        {
                            chunkedParams.Add("chunkedUpload", "true");
                        }
                        chunkedParams.Add("progress", i + "/" + totalChunks);
                        if (fileDone)
                        {
                            chunkedParams.Add("skipappend", "1");
                        }

                        int pos = fileNameIn.LastIndexOf("\\") + 1;

                        // Update timestamp and signature in apiParams with each chunk
                        // Each chunk MUST be able to be sent in the timeout period set by timestamp
                        this.api_timestamp = 0;        // Set to current timestamp
                        apiParams.Remove("api_timestamp");
                        apiParams.Remove("api_signature");
                        apiParams.Add("api_timestamp", this.api_timestamp);
                        this.setSignature(apiParams);
                        apiParams.Add("api_signature", this.getSignature());

                        //var apiParameters = JsonSerializer.Serialize(apiParams);
                        //var chunkedParameters = JsonSerializer.Serialize(chunkedParams);
                        var apiParameters = Newtonsoft.Json.JsonConvert.SerializeObject(apiParams);
                        var chunkedParameters = Newtonsoft.Json.JsonConvert.SerializeObject(chunkedParams);
                        //ASCIIEncoding ascii = new ASCIIEncoding();

                        ByteArrayContent data = null;
                        if (fileDone)
                        {
                            // If file already uploaded, send a single, empty byte so the backend generates a $_FILES array correctly
                            // This is combined with the 'skipappend'=1 parameter to cause the backend to NOT append the single empty byte to the existing file (which is fully uploaded already)
                            data = new ByteArrayContent(new byte[0]);
                        }
                        else
                        {
                            data = new ByteArrayContent(buffer);
                        }
                        data.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("multipart/form-data");

                        //byte[] strParamsBytes = ascii.GetBytes(apiParameters);
                        //byte[] chunkedParamBytes = ascii.GetBytes(chunkedParameters);
                        byte[] bytesParams = Encoding.UTF8.GetBytes(apiParameters);
                        byte[] bytesChunkedParam = Encoding.UTF8.GetBytes(chunkedParameters);

                        HttpClient requestToServer = new HttpClient();
                        requestToServer.Timeout = new TimeSpan(0, 0, timeOutSeconds);
                        MultipartFormDataContent form = new MultipartFormDataContent();
                        form.Add(data, "file", fileNameIn.Substring(pos, fileNameIn.Length - pos));
                        
                        //form.Add(new ByteArrayContent(strParamsBytes), "params");
                        //form.Add(new ByteArrayContent(chunkedParamBytes), "chunkedParams");
                        form.Add(new ByteArrayContent(bytesParams), "params");
                        form.Add(new ByteArrayContent(bytesChunkedParam), "chunkedParams");

                        HttpResponseMessage response = await requestToServer.PostAsync(url, form);
                        if (!response.IsSuccessStatusCode) { throw new Exception(response.ReasonPhrase); }
                        // If code:200 not in response value, then throw exception with content
                        retVal = response.Content.ReadAsStringAsync().Result;
                        if (!retVal.Contains("\"code\":200")) { throw new Exception(retVal); }

                        ulong fileLength = Convert.ToUInt64(fileStream.Length);
                        ulong processedBytes = (ulong)buffer.Length * (ulong)i;
                        ulong total = Convert.ToUInt64(fileLength - processedBytes);

                        if (i < totalChunks)
                        {
                            callback?.Invoke(fileLength, processedBytes, fileNameIn);
                        }

                        if ((fileLength - processedBytes) < Convert.ToUInt64(chunkSize))
                        {
                            buffer = new byte[fileLength - processedBytes];
                        }

                        requestToServer.Dispose();
                        
                        i++;
                        fileDone = false;       // Reset flag to fall out of while loop if this was just an iteration to trigger the encrypt/slice/send because file had already been completely uploaded
                    }
                }
            }
            catch (OperationCanceledException)
            {
                retVal = Newtonsoft.Json.JsonConvert.SerializeObject(new Dictionary<string, object>()
                {
                    { "code", 499 },
                    { "error", new Dictionary<string, object>()
                        {
                            { "errorCode", 499 },
                            { "extendedErrorMessage", "Client Cancelled Upload" },
                        }
                    },
                    { "message", "The upload request was cancelled by the client" },
                });
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR - There was an error sending the chunk request: " + e.Message);
                retVal = e.Message;
            }
            finally
            {
                if (fileStream != null)
                {
                    fileStream.Dispose();
                }
            }

            return retVal;
        }

        public async Task<string> SendFileRequestStream(string fileNameIn, int chunkSize, int timeOutSeconds, Action<ulong, ulong, string> callback, System.Threading.CancellationTokenSource cts, string resumeToken, bool resumeUpload)
        {
            string retVal = "";

            if (this.verbosity) { Console.WriteLine(" - sendFileRequest - "); }
            if (this.url == "") { throw new ArgumentException("Invalid URL"); }
            if (fileNameIn == "" || !System.IO.File.Exists(fileNameIn)) { throw new ArgumentException("A Filename Must Be Specified, or File Does Not Exist"); }
            string guidFile = "STASHFILE_" + System.Guid.NewGuid().ToString();

            FileStream fileStream = null;
            try
            {
                int i = 1;
                string sha256Hash = FileSha256Hash(fileNameIn);

                fileStream = new FileStream(fileNameIn, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: chunkSize, useAsync: true);
                bool fileDone = false;          // Flag to track if file is being resumed from the point its been completely uploaded already (e.g. there was an error with encrypt, slice or sending to storage)

                // If resumeUpload flag set, resumeToken set, and able to seek on the FileStream - try a resume
                if (resumeUpload && resumeToken != "" && fileStream.CanSeek)
                {
                    // Copy the dParams dictionary so it can be reused after GetResumeIndex clears this.dParams
                    //Dictionary<string, object> tDict = this.convertDestinationToSourceDictionary(this.dParams, true);
                    Dictionary<string, object> tDict = this.CopyDictionary(this.dParams);

                    // Get length of file with resumeToken name on server - this will be the position to start from
                    string apiResponseString = this.GetResumeIndex(new Dictionary<string, object>()
                    {
                        { "resumetoken", resumeToken}
                    }, out int retCode, out ulong resumeIndex);

                    if (resumeIndex > 0)
                    {
                        try
                        {
                            fileStream.Seek(Convert.ToInt64(resumeIndex), SeekOrigin.Begin);
                            i = (int)(resumeIndex / Convert.ToUInt64(chunkSize)) + 1;
                            if (Convert.ToUInt64(fileStream.Length) == resumeIndex) { fileDone = true; }
                        }
                        catch (Exception)
                        {
                            // Something failed with seek - reset it to 0 and start upload over again
                            fileStream.Seek(0, SeekOrigin.Begin);
                            resumeIndex = 0;
                            resumeUpload = false;
                        }
                    }
                    this.dParams = tDict;
                }

                // Do not need to set URL because this is a base call, Support File writes, File Writes, Chunked File and Stream Writes will all set the URL before calling this function

                // Build params list containing needed API fields
                System.IO.FileInfo uploadFile = new System.IO.FileInfo(fileNameIn);
                //Dictionary<string, string> chunkedParams = new Dictionary<string, string>();

                //chunkedParams.Add("temp_name", resumeToken);

                if (uploadFile.Length <= chunkSize)
                {
                    chunkSize = Convert.ToInt32(uploadFile.Length);  // if the file is smaller than the chunk size, upload the file as one chunk
                }

                //byte[] buffer = new byte[chunkSize];

                //Int32 bytesRead = 0;
                //var responseString = string.Empty;

                Dictionary<string, object> apiParams = new Dictionary<string, object>();
                apiParams.Add("url", this.url);
                apiParams.Add("api_version", this.api_version);
                apiParams.Add("api_id", this.api_id);
                this.api_timestamp = 0;        // Set to current timestamp
                apiParams.Add("api_timestamp", this.api_timestamp);
                apiParams.Add("file_guid", guidFile);
                // Sign Request
                Dictionary<string, object> mergedDictionaries = Dictionaries_merge(apiParams, this.dParams);
                if ((this.dParams != null) && this.dParams.Count > 0)
                {
                    this.setSignature(mergedDictionaries);
                }
                else
                {
                    this.setSignature(apiParams);
                }
                apiParams.Add("api_signature", this.getSignature());

                StreamContent streamData = new StreamContent(fileStream, chunkSize);
                
                streamData.Headers.Add("x-stash-api-id", this.api_id);
                streamData.Headers.Add("x-stash-api-signature", this.getSignature());
                streamData.Headers.Add("x-stash-api-timestamp", this.api_timestamp.ToString());
                streamData.Headers.Add("x-stash-api-version", this.api_version);
                streamData.Headers.Add("x-stash-api-params", Newtonsoft.Json.JsonConvert.SerializeObject(mergedDictionaries));
                streamData.Headers.Add("x-stash-size", uploadFile.Length.ToString());
                streamData.Headers.Add("x-stash-filename", uploadFile.Name);
                streamData.Headers.Add("x-stash-sha256hash", sha256Hash);
                // ToDo fix...
                //streamData.Headers.Add("content-type", "");

                HttpClient requestToServer = new HttpClient();
                requestToServer.Timeout = new TimeSpan(0, 0, timeOutSeconds);

                HttpResponseMessage response = await requestToServer.PostAsync(url, streamData);
                if (!response.IsSuccessStatusCode) { throw new Exception(response.ReasonPhrase); }
                // If code:200 not in response value, then throw exception with content
                retVal = response.Content.ReadAsStringAsync().Result;
                if (!retVal.Contains("\"code\":200")) { throw new Exception(retVal); }

                if (retVal.Contains("sha256hash"))
                {
                    // Check hash values from local file and reported by server and error if they are different
                    // Format being looked for "sha256hash":"abcd..."
                    string keyString = "\"sha256hash\":";
                    int keyStrStart = retVal.IndexOf(keyString);
                    int hashStrStart = keyStrStart + keyString.Length + 1; // +1 for the : and " after the sha256hash and before the start of the actual hash
                    int hashStrEnd = retVal.IndexOf("\"", hashStrStart);
                    string strHash = retVal.Substring(hashStrStart, hashStrEnd - hashStrStart);
                
                    if (strHash != sha256Hash) { 
                        throw new Exception("File Hashes do not Match - Source and Received File on Server are Different. Delete the File on the Server, Restore Previous Version on the Server, or Try Your Upload Again."); 
                    }
                }
            }
            catch (OperationCanceledException)
            {
                retVal = Newtonsoft.Json.JsonConvert.SerializeObject(new Dictionary<string, object>()
                {
                    { "code", 499 },
                    { "error", new Dictionary<string, object>()
                        {
                            { "errorCode", 499 },
                            { "extendedErrorMessage", "Client Cancelled Upload" },
                        }
                    },
                    { "message", "The upload request was cancelled by the client" },
                });
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR - There was an error: " + e.Message);
                retVal = e.Message;
            }
            finally
            {
                if (fileStream != null)
                {
                    fileStream.Dispose();
                }
            }

            return retVal;
        }

        // Validate the source identifier parameters
        // * Source identifier can contain fileId, fileName, folderNames, folderId
        // * To be valid, a fileId Or (fileName And (folderId Or folderNames)) must be given
        // * If folderOnly Is T, then fileId And fileName need Not be specified
        // * allowZeroIds is T if the validation should allow for folderId and/or fileId to be zero and/or the folderId to be -1 (all folders)
        //
        public bool validateSourceParams(bool folderOnly, bool allowZeroIds = false)
        {
            if (folderOnly)
            {
                if (allowZeroIds)
                {
                    if (this.dParams.TryGetValue("folderId", out object tFolderId) && tFolderId != null && Convert.ToInt64(tFolderId) >= -1) { return true; }
                }
                else
                {
                    if (this.dParams.TryGetValue("folderId", out object tFolderId) && tFolderId != null && Convert.ToInt64(tFolderId) > 0) { return true; }
                }
                if (this.dParams.TryGetValue("folderNames", out object tFolderNames) && tFolderNames != null)
                {
                    string[] strFolderNames = (string[])tFolderNames;
                    if (strFolderNames.Length > 0) { return true; }
                }
                if (this.dParams.TryGetValue("filePath", out object tFilePath) && tFilePath != null && tFilePath.ToString() != "") { return true; }
                throw new ArgumentException("Source Parameters Invalid - folderId or folderNames or filePath MUST be specified");
            }
            else
            {
                if (allowZeroIds)
                {
                    if (this.dParams.TryGetValue("fileId", out object tFileId) && tFileId != null && Convert.ToUInt64(tFileId) >= 0) { return true; }
                }
                else
                {
                    if (this.dParams.TryGetValue("fileId", out object tFileId) && tFileId != null && Convert.ToUInt64(tFileId) > 0) { return true; }
                }
                if (this.dParams.TryGetValue("fileName", out object tFileName) && tFileName != null && tFileName.ToString() != "")
                {
                    if (this.dParams.TryGetValue("folderId", out object tFolderId) && tFolderId != null && Convert.ToUInt64(tFolderId) > 0) { return true; }
                    if (this.dParams.TryGetValue("folderNames", out object tFolderNames) && tFolderNames != null)
                    {
                        string[] strFolderNames = (string[])tFolderNames;
                        if (strFolderNames.Length > 0) { return true; }
                    }
                }
                if (this.dParams.TryGetValue("filePath", out object tFilePath) && tFilePath != null && tFilePath.ToString() != "") { return true; }
                throw new ArgumentException("Source Parameters Invalid - fileId or fileName plus either folderId or folderNames, or filePath MUST be specified");
            }
        }

        // Validate the destination identifier parameters
        // * To be valid, destFileName And (destFolderId Or destFolderNames) must be given
        // * If folderOnly Is T, then destFileName need Not be given
        // * If nameOnly Is T, then destFolderId And destFolderNames need Not be given (but folderOnly must be false)
        // 
        public bool validateDestParams(bool folderOnly, bool nameOnly)
        {
            if (folderOnly && nameOnly)
            {
                throw new ArgumentException("folderOnly and nameOnly cannot both be TRUE");
            }

            if (folderOnly)
            {
                if (this.dParams.TryGetValue("destFolderId", out object tDestFolderId) && tDestFolderId != null && Convert.ToUInt64(tDestFolderId) > 0) { return true; }
                if (this.dParams.TryGetValue("destFilePath", out object tDestFilePath) && tDestFilePath != null && tDestFilePath.ToString() != "") { return true; }
                if (this.dParams.TryGetValue("destFolderNames", out object tDestFolderNames) && tDestFolderNames != null)
                {
                    string[] strDestFolderNames = (string[])tDestFolderNames;
                    if (strDestFolderNames.Length > 0) { return true; }
                }
                throw new ArgumentException("Destination Parameters Invalid - destFolderId or destFolderNames MUST be specified");
            }
            else
            {
                if (this.dParams.TryGetValue("destFileName", out object tDestFileName) && (tDestFileName != null) && tDestFileName.ToString() != "")
                {
                    if (nameOnly) { return true; }
                    if (this.dParams.TryGetValue("destFolderId", out object tDestFolderId) && tDestFolderId != null && Convert.ToUInt64(tDestFolderId) > 0) { return true; }
                    if (this.dParams.TryGetValue("destFilePath", out object tDestFilePath) && tDestFilePath != null && tDestFilePath.ToString() != "") { return true; }
                    if (this.dParams.TryGetValue("destFolderNames", out object tDestFolderNames) && tDestFolderNames != null)
                    {
                        string[] strDestFolderNames = (string[])tDestFolderNames;
                        if (strDestFolderNames.Length > 0) { return true; }
                    }
                }
                throw new ArgumentException("Destination Parameters Invalid - destFileName plus either destFolderId or destFolderNames MUST be specified");
            }
        }

        // Function validates the output type parameters
        // Source identifier must contain outputType equal to one of the APIRequest::API_OUTPUT_TYPE_X constants
        public bool validateOutputParams()
        {
            if (this.dParams.TryGetValue("outputType", out object tOutputType) && tOutputType != null && Convert.ToUInt64(tOutputType) >= 0) { return true; }
            throw new ArgumentException("Source Parameters Invalid - outputType MUST be specified");
        }

        // Function validates the search parameters
        public bool validateSearchParams(bool requireTerms)
        {
            if (requireTerms)
            {
                if (this.dParams.TryGetValue("search", out object tSearch) && tSearch != null && Convert.ToString(tSearch) != "") { return true; }
                throw new ArgumentException("Search Terms Invalid - search parameter MUST be specified");
            }
            return true;
        }

        // Function validates the version parameter
        public bool validateVersionParams()
        {
            if (this.dParams.TryGetValue("version", out object tVersion) && tVersion != null && Convert.ToString(tVersion) != "" && IsNumeric(tVersion)) { return true; }
            throw new ArgumentException("Version Parameter Invalid - version parameter MUST be specified as a number");
        }

        // Function validates the smart folder ID parameter
        public bool validateSmartFolderId()
        {
            if (this.dParams.TryGetValue("sfId", out object tSfId) && tSfId != null && Convert.ToUInt64(tSfId) > 0) { return true; }
            throw new ArgumentException("Invalid SmartFolder ID");
        }

        // Function validates the overwriteFile parameter and corresponding overwriteFileId parameter, which is required if overwriteFile is specified
        public bool validateOverwriteParams()
        {
            if (this.dParams.TryGetValue("overwriteFile", out object objOverwriteFile) && objOverwriteFile != null)
            {
                byte overwriteFile = Convert.ToByte(objOverwriteFile);
                if (overwriteFile > 1 || overwriteFile < 0) { throw new ArgumentException("Invalid overwriteFile value"); }
                if (overwriteFile == 1)     // overwriteFileId MUST be specified
                {
                    if (!this.dParams.TryGetValue("overwriteFileId", out object objFileId) || objFileId == null)
                    {
                        throw new ArgumentException("overwriteFileId parameter must be specified with overwriteFile");
                    }
                    if (Convert.ToUInt64(objFileId) < 1)
                    {
                        throw new ArgumentException("Invalid value for overwriteFileId");
                    }
                }
            }
            return true;
        }

        // Function validates the check cred parameters
        // Source identifier can contain fileKey, accountUsername, apiid, apipw
        //
        // @param Boolean, T if the validation should check fileKey
        // @param Boolean, T if the validation should check accountUsername
        // @param Boolean, T if the validation should check apiid
        // @param Boolean, T if the validation should check apipw
        // @return Boolean, T if the parameters are valid
        //
        public bool validateCredParams(bool checkFileKey, bool checkUsername, bool checkApiId, bool checkApiPw)
        {
            if (checkFileKey)
            {
                this.dParams.TryGetValue("fileKey", out object tFileKey);
                if (tFileKey == null || tFileKey.ToString() == "") { throw new ArgumentException("Source Parameters Invalid - fileKey MUST be specified and not blank"); }
            }

            if (checkUsername)
            {
                this.dParams.TryGetValue("accountUsername", out object tUsername);
                if (tUsername == null || tUsername.ToString() == "") { throw new ArgumentException("Source Parameters Invalid - accountUsername MUST be specified and not blank"); }
            }

            if (checkApiId)
            {
                this.dParams.TryGetValue("apiid", out object tApiId);
                if (tApiId == null || tApiId.ToString() == "") { throw new ArgumentException("Source Parameters Invalid - apiid MUST be specified and not blank"); }
            }

            if (checkApiPw)
            {
                this.dParams.TryGetValue("apipw", out object tApiPw);
                if (tApiPw == null || tApiPw.ToString() == "") { throw new ArgumentException("Source Parameters Invalid - apipw MUST be specified and not blank"); }
            }

            return true;
        }

        // Function valides the set permissions parameters
        public bool validateSetPermParams()
        {
            if (this.dParams.TryGetValue("permJson", out object tJson) && tJson != null && Convert.ToString(tJson) != "") { return true; }
            throw new ArgumentException("Invalid permissions Json parameter");
        }

        // Function validates the check permissions parameters
        public bool validateCheckPermParams()
        {
            if (this.dParams.TryGetValue("objectUserId", out object tObjectUserId) && tObjectUserId == null || Convert.ToUInt64(tObjectUserId) < 1)
            {
                throw new ArgumentException("Invalid objectUserId parameter");
            }
            if (this.dParams.TryGetValue("objectId", out object tObjectId) && tObjectId == null || Convert.ToUInt64(tObjectId) < 1)
            {
                throw new ArgumentException("Invalid objectId parameter");
            }
            if (this.dParams.TryGetValue("objectIdType", out object tObjectIdType) && tObjectIdType == null || Convert.ToUInt64(tObjectIdType) < 1)
            {
                throw new ArgumentException("Invalid objectIdType parameter");
            }
            if (this.dParams.TryGetValue("requestedAccess", out object tRequestedAccess) && tRequestedAccess == null || Convert.ToInt64(tRequestedAccess) < 0)
            {
                throw new ArgumentException("Invalid requestedAccess parameter");
            }

            return true;
        }

        // Function validates the WebErase Request Parameters
        public bool ValidateWebEraseParams(bool tokenOnly)
        {
            // Verify the token
            if (this.dParams.TryGetValue("token_key", out object tToken) && tToken == null || tToken.ToString() == "")
            {
                throw new ArgumentException("Invalid token_key parameter");
            }

            if (!tokenOnly)
            {
                if (this.dParams.TryGetValue("fileKey", out object tFileKey) && tFileKey == null || tFileKey.ToString() == "")
                {
                    throw new ArgumentException("Invalid fileKey parameter");
                }
            }

            return true;
        }

        public bool ValidateWebEraseStoreParams()
        {
            // Verify the token
            if (this.dParams.TryGetValue("token_key", out object tToken) && tToken == null || tToken.ToString() == "")
            {
                throw new ArgumentException("Invalid token_key parameter");
            }

            if (this.dParams.TryGetValue("fileKey", out object tFileKey) && tFileKey == null || tFileKey.ToString() == "")
            {
                throw new ArgumentException("Invalid fileKey parameter");
            }

            if (this.dParams.TryGetValue("destFolderId", out object tFolderId) && tFolderId == null || Convert.ToInt32(tFolderId.ToString()) < 1)
            {
                throw new ArgumentException("Invalid destFolderId parameter");
            }

            return true;
        }

        // Function validates the tag(s) parameters
        public bool validateSourceTags(bool singleTag)
        {
            if (singleTag)
            {
                // Expect only a single string
                if (this.dParams.TryGetValue("tag", out object tTag) && tTag != null && Convert.ToString(tTag) != "") { return true; }
                throw new ArgumentException("Tag String Invalid - tag parameter MUST be specified");
            }
            else
            {
                if (this.dParams.TryGetValue("tags", out object tTags) && tTags != null && Convert.ToString(tTags) != "") { return true; }
                throw new ArgumentException("Tags String Invalid - tags parameter MUST be specified");
            }
        }

        // Function validates the input parameters before they are passed to the API endpoint
        public virtual bool validateParams(string opIn)
        {
            bool retVal = false;
            opIn = opIn.ToLower();

            try
            {
                if (this.dParams == null && opIn != "none") { throw new ArgumentException("Parameters Can't Be Null"); }

                // Set the subsystem and operation if URL contains them
                if (this.url != "")
                {
                    // Parse urlIn to get the subsystem and operation 
                    string[] listUrl = this.url.Split("/");
                    if (listUrl.Length == 6)
                    {
                        this.apiSubsystem = listUrl[4] != null ? listUrl[4] : "";
                        this.apiOperation = listUrl[5] != null ? listUrl[5] : "";
                    }
                }

                if (opIn == "read")
                {
                    this.validateSourceParams(false, false);
                    if (!this.dParams.TryGetValue("fileKey", out object tFileKey) || tFileKey == null || tFileKey.ToString() == "")
                    {
                        throw new ArgumentException("Invalid fileKey Parameter");
                    }
                }
                else if (opIn == "write")
                {
                    this.validateDestParams(true, false);
                    this.validateOverwriteParams();
                    if (!this.dParams.TryGetValue("fileKey", out object tFileKey) || tFileKey == null || tFileKey.ToString() == "")
                    {
                        throw new ArgumentException("Invalid fileKey Parameter");
                    }
                }
                else if (opIn == "resumeindex")
                {
                    if (!this.dParams.TryGetValue("resumetoken", out object tToken) || tToken == null || tToken.ToString() == "")
                    {
                        throw new ArgumentException("Invalid resumetoken Parameter");
                    }
                }
                else if (opIn == "copy")
                {
                    this.validateSourceParams(false, false);
                    this.validateDestParams(false, false);
                }
                else if (opIn == "delete")
                {
                    this.validateSourceParams(false, false);
                }
                else if (opIn == "rename")
                {
                    this.validateSourceParams(false, false);
                    this.validateDestParams(false, true);
                }
                else if (opIn == "move")
                {
                    this.validateSourceParams(false, false);
                    this.validateDestParams(true, false);
                }
                else if (opIn == "listall")
                {
                    this.validateSourceParams(true, true);
                    this.validateSearchParams(false);
                }
                else if (opIn == "listfiles")
                {
                    this.validateSourceParams(true, true);
                    this.validateOutputParams();
                    this.validateSearchParams(false);
                }
                else if (opIn == "listsffiles")
                {
                    this.validateOutputParams();
                    this.validateSmartFolderId();
                }
                else if (opIn == "listfolders")
                {
                    this.validateSourceParams(true, true);
                    this.validateOutputParams();
                    this.validateSearchParams(false);
                }
                else if (opIn == "getfolderid")
                {
                    this.validateSourceParams(true, false);
                }
                else if (opIn == "createdirectory")
                {
                    this.validateSourceParams(true, false);
                }
                else if (opIn == "deletedirectory")
                {
                    this.validateSourceParams(true, false);
                }
                else if (opIn == "renamedirectory")
                {
                    this.validateSourceParams(true, false);
                    this.validateDestParams(true, false);
                }
                else if (opIn == "movedirectory")
                {
                    this.validateSourceParams(true, false);
                    this.validateDestParams(true, false);
                }
                else if (opIn == "copydirectory")
                {
                    this.validateSourceParams(true, false);
                    this.validateDestParams(true, false);
                }
                else if (opIn == "getfileinfo")
                {
                    this.validateSourceParams(false, false);
                }
                else if (opIn == "getfolderinfo")
                {
                    this.validateSourceParams(true, false);
                }
                else if (opIn == "setfilelock")
                {
                    this.validateSourceParams(false, false);
                }
                else if (opIn == "getfilelock")
                {
                    this.validateSourceParams(false, false);
                }
                else if (opIn == "clearfilelock")
                {
                    this.validateSourceParams(false, false);
                }
                else if (opIn == "settags")
                {
                    this.validateSourceParams(false, false);
                    this.validateSourceTags(false);
                }
                else if (opIn == "gettags")
                {
                    this.validateSourceParams(false, false);
                }
                else if (opIn == "addtag")
                {
                    this.validateSourceParams(false, false);
                    this.validateSourceTags(true);
                }
                else if (opIn == "deletetag")
                {
                    this.validateSourceParams(false, false);
                    this.validateSourceTags(true);
                }
                else if (opIn == "getsyncinfo")
                {
                    this.validateSourceParams(true, false);
                }
                else if (opIn == "checkcreds")
                {
                    this.validateCredParams(true, true, false, false);
                }
                else if (opIn == "checkcredsad")
                {
                    this.validateCredParams(true, true, false, false);
                }
                else if (opIn == "isvaliduser")
                {
                    this.validateCredParams(false, true, false, false);
                }
                else if (opIn == "getuserid")
                {
                    this.validateCredParams(false, true, false, false);
                }
                else if (opIn == "getsecret")
                {
                    this.api_id = "01010101010101010101010101010101";       // Set to nonsense ID, an ID is not needed for this request
                    this.api_pw = this.api_id;       // Set to 'known' string, it will be used to sign the request only
                    this.validateCredParams(false, true, false, false);
                    if (!this.dParams.TryGetValue("pubkey", out object tPubKey) || tPubKey == null || tPubKey.ToString() == "")
                    {
                        throw new ArgumentException("Invalid pubkey Parameter");
                    }
                }
                else if (opIn == "getapicreds")
                {
                    this.api_id = "01010101010101010101010101010101";       // Set to nonsense ID, an ID is not needed for this request
                    this.api_pw = this.api_id;       // Set to 'known' string, it will be used to sign the request only
                    this.validateCredParams(true, true, false, false);
                    if (!this.dParams.TryGetValue("id", out object tId) || tId == null || tId.ToString() == "")
                    {
                        throw new ArgumentException("Invalid id Parameter");
                    }
                }
                else if (opIn == "setperms")
                {
                    this.validateSetPermParams();
                }
                else if (opIn == "checkperms")
                {
                    this.validateCheckPermParams();
                }
                else if (opIn == "listversions")
                {
                    this.validateSourceParams(false, false);
                }
                else if (opIn == "readversion")
                {
                    this.validateSourceParams(false, false);
                    this.validateVersionParams();
                }
                else if (opIn == "restoreversion")
                {
                    this.validateSourceParams(false, false);
                    this.validateVersionParams();
                }
                else if (opIn == "deleteversion")
                {
                    this.validateSourceParams(false, false);
                    this.validateVersionParams();
                }
                else if (opIn == "weberasetoken")
                {
                    // No specific parameters needed
                    retVal = true;
                }
                else if (opIn == "weberaseprojectlist")
                {
                    // No specific parameters needed
                    retVal = true;
                }
                else if (opIn == "weberasestore")
                {
                    this.ValidateWebEraseStoreParams();
                }
                else if (opIn == "weberaseretrieve")
                {
                    this.ValidateWebEraseParams(false);
                }
                else if (opIn == "weberaseupdate")
                {
                    this.ValidateWebEraseParams(false);
                }
                else if (opIn == "weberasedelete")
                {
                    this.ValidateWebEraseParams(true);
                }
                else if (opIn == "weberaseotc")
                {
                    this.ValidateWebEraseParams(true);
                }
                else if (opIn == "weberasepolling")
                {
                    this.ValidateWebEraseParams(true);
                }
                else if (opIn == "none")
                {
                    retVal = true;
                }
                else
                {
                    throw new Exception("Unrecognized Operation Specified");
                }
                retVal = true;
            }
            catch (Exception ex)
            {
                retVal = false;
                Console.WriteLine("ERROR - STAHSAPI.cs::ValidateParams() - Error - " + ex.Message);
            }
            return retVal;
        }

        // Convert a dictionary object to a string representation for debugging purposes
        //
        public string DictToString(Dictionary<string, object> dictIn)
        {
            string s = "";
            try
            {
                foreach (KeyValuePair<string, object> kvp in dictIn)
                {
                    if (kvp.Value == null)
                    {
                        continue;
                    }
                    s = s + String.Format("{0}=", kvp.Key.ToString());
                    if (kvp.Value.GetType() == typeof(string[]))
                    {
                        s = s + "[";                     // Open text representation of array
                        foreach (string strItem in (string[])kvp.Value)
                        {
                            s = s + String.Format("{0},", strItem);
                        }
                        if (s.Substring(s.Length - 1, 1) == ",")
                        {
                            s = s.Substring(0, s.Length - 1);               // Strip off trailing comma
                        }
                        s = s + "]";                      // Close text representation of array
                    }
                    else if (kvp.Value.GetType() == typeof(string) || IsNumeric(kvp.Value))
                    {
                        s = s + String.Format("{0}", kvp.Value.ToString()) + ",";
                    }
                    else if (kvp.Value.GetType() == typeof(Array))
                    {
                        s = s + "Array Type" + ",";
                    }
                    else if (kvp.Value.GetType() == typeof(System.Collections.Generic.Dictionary<string, object>))
                    {
                        Dictionary<string, object> tDict = (Dictionary<string, object>)kvp.Value;
                        s = s + DictToString(tDict);
                    }
                    else if (kvp.Value.GetType() == typeof(System.Object[]))
                    {
                        object[] objArray = (object[])kvp.Value;
                        int numElements = objArray.Length;
                        for (int i = 0; i <= numElements - 1; i++)
                        {
                            s = s + "Object: " + objArray[i].ToString();
                        }
                    }
                    else if (kvp.Value.GetType() == typeof(System.Text.Json.JsonElement))
                    {
                        s = s + String.Format("{0}", ((JsonElement)kvp.Value).ToString()) + ",";
                    }
                    else
                    {
                        s = s + "Unknown data type in dictionary, Type: " + kvp.Value.GetType().ToString() + ",";
                    }
                }
                if (s.Substring(s.Length - 1, 1) == ",")
                {
                    s = s.Substring(0, s.Length - 1);               // Strip off trailing comma
                }
            }
            catch (Exception ex)
            {
                string msg = ex.Message;
                s = "An error occurred converting dictionary to string";
            }
            return s;
        }

        // Loose implementation of PHP's http_build_query function which URL encodes certain values in a string
        // @deprecated - use JsonSerializer.Serialize()
        //public string Http_build_query(Dictionary<string, object> dataIn)
        //{
        //    string tStr = "";
        //    foreach (KeyValuePair<string, object> kvp in dataIn)
        //    {
        //        if (kvp.Value.GetType().Equals(typeof(string)) || IsNumeric(kvp.Value))
        //        {
        //            tStr = String.Concat(tStr, (tStr == "" ? "" : "&"), kvp.Key, "=", HttpUtility.UrlEncode(kvp.Value.ToString()));
        //        }
        //        else
        //        {
        //            if (kvp.Value.GetType().Equals(typeof(string[])))
        //            {
        //                int counter = 0;
        //                foreach (string strItem in (string[])kvp.Value)
        //                {
        //                    tStr = String.Concat(tStr, (tStr == "" ? "" : "&"), HttpUtility.UrlEncode(String.Format("{0}[{1}]", kvp.Key, counter.ToString())), "=", HttpUtility.UrlEncode(strItem));
        //                    counter++;
        //                }
        //            }
        //            else if (kvp.Value.GetType().Equals(typeof(System.Guid)))
        //            {
        //                tStr = String.Concat(tStr, (tStr == "" ? "" : "&"), kvp.Key, "=", HttpUtility.UrlEncode(kvp.Value.ToString()));
        //            }
        //            else if (kvp.Value.GetType().Equals(typeof(Boolean)))
        //            {
        //                tStr = String.Concat(tStr, (tStr == "" ? "" : "&"), kvp.Key, "=", HttpUtility.UrlEncode((kvp.Value.Equals(true) ? "1" : "0")));
        //            }
        //            else
        //            {
        //                throw new Exception("Dictionary Value Conversion Not Implemented in Http_build_query(), Type: " + kvp.Value.GetType().ToString());
        //            }
        //        }
        //    }
        //    // Manual character replacement, $-_.+!*'(),  need to be replaced, see RFC 1738 - http://www.ietf.org/rfc/rfc1738.txt
        //    tStr = tStr.Replace("(", "%28");
        //    tStr = tStr.Replace(")", "%29");
        //    tStr = tStr.Replace("*", "%2A");
        //    tStr = tStr.Replace("!", "%21");

        //    // Change all %2x and %3x and similar codes to uppercase, to match PHP's http_build_query function
        //    Regex reg = new Regex("%[a-f0-9]{2}");
        //    tStr = reg.Replace(tStr, new MatchEvaluator(regexToUpper));

        //    return tStr;
        //}

        // Converts strings to uppercase, used by Regex handling
        public string regexToUpper(Match m)
        {
            return m.ToString().ToUpper();
        }

        // Converts strings to lowercase, used by Regex handling
        public string regexToLower(Match m)
        {
            return m.ToString().ToLower();
        }

        // Computes the HMAC HASH of a string
        public string Hash_hmac(string strAlgorithm, string strString, string strKey)
        {
            string retVal = "";
            HMACSHA256 objHMAC;
            byte[] tBytes;

            if (strString == "") { return ""; }
            if (strKey == null || strKey == "") { throw new Exception("Invalid Key Provided"); }

            if (strAlgorithm == "sha256")
            {
                objHMAC = new HMACSHA256(System.Text.Encoding.UTF8.GetBytes(strKey));
                tBytes = objHMAC.ComputeHash(System.Text.Encoding.UTF8.GetBytes(strString));
                for (int i = 0; i < tBytes.Length; i++)
                {
                    retVal = retVal + tBytes[i].ToString("X2");
                }
            }
            else
            {
                throw new Exception("Algorithm not Supported");
            }

            return retVal;
        }

        // Merges the key/value pairs of two dictionaries
        public Dictionary<string, object> Dictionaries_merge(Dictionary<string, object> dict1, Dictionary<string, object> dict2)
        {
            Dictionary<string, object> retDict = new Dictionary<string, object>();

            retDict = dict1;
            foreach (KeyValuePair<string, object> kvp in dict2)
            {
                retDict.Add(kvp.Key, kvp.Value);
            }
            return retDict;
        }

        // Generates a random string from the defined character set of size _numChars_
        public string genRandomString(int numChars)
        {
            string charSet = "abcdefghijklmnopqrstuvwxyz1234567890";
            Random rnd = new Random();
            StringBuilder retVal = new StringBuilder();
            for (int i = 1; i <= numChars; i++)
            {
                int numChar = rnd.Next(0, 35);
                retVal.Append(charSet.Substring(numChar, 1));
            }
            return retVal.ToString();
        }

        // Converts a hex string to a binary string
        public string hex2bin(string hexIn)
        {
            string bin = "";
            string hexStr = "";

            if ((hexIn.Length % 2) != 0)
            {
                throw new ArgumentException("Input String Must be Even Number of Characters");
            }

            for (int i = 0; i <= hexIn.Length - 1; i = i + 2)
            {
                hexStr = hexIn[i].ToString() + hexIn[i + 1].ToString();
                int tVal = Convert.ToInt32(hexStr, 16);
                bin = bin + (char)tVal;
            }
            return bin;
        }

        // Converts a binary string to a hex string
        public string bin2hex(string strIn)
        {
            string retVal = "";
            StringBuilder hexStr = new StringBuilder();

            foreach (char ch in strIn)
            {
                byte b = (byte)ch;
                int h = Convert.ToInt32(b.ToString(), 16);
                hexStr.Append(h.ToString().PadLeft(2, '0'));
            }
            Regex reg = new Regex("[A-F]");
            retVal = reg.Replace(hexStr.ToString(), new MatchEvaluator(regexToLower));      // For compat with PHP's bin2hex which outputs lowercase hexbits
            return retVal;
        }

        // Converts a byte array to a string of bytes separated by :
        public string arr2Str(byte[] bytesIn)
        {
            string tStr = "";

            for (int i = 0; i <= bytesIn.Length - 1; i++)
            {
                tStr = tStr + bytesIn[i].ToString() + ":";
            }
            tStr = tStr.Substring(0, tStr.Length - 1);      // Trim off final ":"
            return tStr;
        }

        public bool IsValidURL(string val)
        {
            if (val == "")
            {
                return false;
            }

            if (val.Substring(0, 5).ToLower() != "https")
            {
                return false;
            }

            bool result = Uri.TryCreate(val, UriKind.Absolute, out Uri uriResult) && (uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps);

            return result;
        }

        // *********************************************************************************************
        // STASH API HELPER FUNCTIONS
        // *********************************************************************************************
        // Downloads a file from the user's vault
        public string getFile(Dictionary<string, object> srcIdentifier, string fileNameOut, ulong fileSize, int timeOut, Action<ulong, ulong, string> callback, CancellationTokenSource cts, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = new Dictionary<string, object>();

            if (fileNameOut == null || fileNameOut == "")
            {
                throw new ArgumentException("An Output File Name Must be Specified");
            }

            // Check fileNameOut contains a valid path
            System.IO.FileInfo fInfo = new System.IO.FileInfo(fileNameOut);
            if (!fInfo.Directory.Exists)
            {
                throw new Exception("Incorrect Output File Path or Path Does Not Exist");
            }

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/read";

            if (!this.validateParams("read")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.sendDownloadRequest(fileNameOut, fileSize, timeOut, callback, cts, out retCode);
            if (this.dParams != null) { this.dParams.Clear(); }

            if (apiResult == "1")
            {   // Simulate a 200 OK if command succeeds
                retCode = 200;
                retVal.Add("code", "200");
                retVal.Add("message", "OK");
                retVal.Add("fileName", fileNameOut);
                //apiResult = JsonSerializer.Serialize(retVal);
                apiResult = Newtonsoft.Json.JsonConvert.SerializeObject(retVal);
            }

            return apiResult;
        }

        // Uploads file to the user's Vault
        public Dictionary<string, object> putFile(string fileNameIn, Dictionary<string, object> srcIdentifier, int timeOut, out int retCode, out UInt64 fileId, out UInt64 fileAliasId)
        {
            CancellationTokenSource cts = new CancellationTokenSource();
            Action<ulong, ulong, string> callback = (fileSize, processedBytes, name) =>
            {
                // Empty
            };

            // Chunk size is arbitrary - if file is smaller than chunk size, it will send it all in one chunk
            // Resume token isn't used in putFile()
            return this.putFileChunked(fileNameIn, srcIdentifier, 1000000, timeOut, callback, cts, out string resumeToken, out retCode, out fileId, out fileAliasId);
        }

        /// <summary>
        /// Uploads a file to the Vault Support system
        /// This is used to transmit log/troubleshooting data from clients to a central repository on the server
        /// </summary>
        /// <param name="fileNameIn">string - the full path and filename to upload</param>
        /// <param name="timeOut">int - the timeout value for the upload, in seconds</param>
        /// <param name="retCode">int - output, the return code from the upload (e.g. 200, 404, etc) </param>
        /// <param name="msg">string - output, the error message if one occurs</param>
        /// <param name="extMsg">string - output, the extended error message, if one occurs</param>
        /// <returns>Dictionary<string,object> - the response from the API call to writesupport</returns>
        /// <exception cref="Exception"></exception>
        public Dictionary<string, object> putFileSupport(string fileNameIn, Dictionary<string, object> srcIdentifier, int timeOut, out int retCode, out string msg, out string extMsg)
        {
            string apiResult = ""; msg = ""; extMsg = ""; retCode = 0;
            Dictionary<string, object> retVal = null;

            System.IO.FileInfo fInfo = new System.IO.FileInfo(fileNameIn);
            if (!fInfo.Exists)
            {
                throw new Exception("Incorrect Input File Path or File Does Not Exist");
            }

            this.url = this.BASE_API_URL + "api2/support/writesupport";
            this.dParams = srcIdentifier;
            apiResult = this.SendFileRequest(fileNameIn, timeOut);

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200)
            {
                GetError(retVal, out retCode, out msg, out extMsg);
                if (this.verbosity)
                {
                    Console.WriteLine("- Error Occurred putFileSupport, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }

            return retVal;
        }

        // Uploads file to the user's Vault using Chunks
        public Dictionary<string, object> putFileChunked(string fileNameIn, Dictionary<string, object> srcIdentifier, int chunkSize, int timeOut, Action<ulong, ulong, string> callback, System.Threading.CancellationTokenSource cts, out string resumeToken, out int retCode, out UInt64 fileId, out UInt64 fileAliasId)
        {
            string apiResult = "";

            retCode = 0;
            fileId = 0; fileAliasId = 0;
            Dictionary<string, object> retVal = null;
            
            System.IO.FileInfo fInfo = new System.IO.FileInfo(fileNameIn);
            if (!fInfo.Exists)
            {
                throw new Exception("Incorrect Input File Path or File Does Not Exist");
            }

            bool resumeUpload = false;
            if (srcIdentifier.TryGetValue("resumetoken", out object objResumeToken))
            {
                // The resumetoken was provided in the request parameters, use it to resume the upload
                resumeToken = "";
                if (objResumeToken != null)
                {
                    resumeToken = objResumeToken.ToString();
                }
                resumeUpload = true;
            }
            else
            {
                // Generate a temp name for the server to store the file. This prevents files of the same name from confilicting with each other.
                // This becomes the token for resuming uploads
                //const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                //Random random = new Random();
                //resumeToken = new string(Enumerable.Repeat(chars, 24)
                //  .Select(s => s[random.Next(s.Length)]).ToArray());
                //resumeToken += fInfo.Extension;        // Add file extension
                resumeToken = System.Guid.NewGuid().ToString().Replace("-", String.Empty);
            }

            // If the destFileName isn't present - add it - this will prevent the backend from using the $_FILES array for the filename which may have different formats for unicode strings
            if (!srcIdentifier.TryGetValue("destFileName", out object tDestFileName))
            {
                srcIdentifier.Add("destFileName", System.IO.Path.GetFileName(fileNameIn));
            }

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/writechunked";
            if (!this.validateParams("write")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendFileRequestChunked(fileNameIn, chunkSize, timeOut, callback, cts, resumeToken, resumeUpload).Result;
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                object fileAliasIdObj;
                object fileIdObj;
                retVal.TryGetValue("fileAliasId", out fileAliasIdObj);
                retVal.TryGetValue("fileId", out fileIdObj);
                if (fileAliasIdObj != null)
                {
                    fileAliasId = Convert.ToUInt64(fileAliasIdObj.ToString());
                }
                if (fileIdObj != null)
                {
                    fileId = Convert.ToUInt64(fileIdObj.ToString());
                }
            } else if (retCode == -1)
            {
                // Custom error message is in apiResult
                throw new Exception(apiResult);
            }
            else
            {
                GetError(retVal, out retCode, out string msg, out string extMsg);
                if (this.verbosity)
                {
                    Console.WriteLine("- Error Occurred putFileChunked, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }
            return retVal;
        }

        /// <summary>
        /// Uploads a file to the user's Vault using a stream
        /// The advantange of this method is that the file is not written to the Vault server hard drives until it is encrypted
        /// </summary>
        /// <param name="fileNameIn">the name and path of the file to upload</param>
        /// <param name="srcIdentifier">the Source identifier containing where the file should be uploaded in the Vault</param>
        /// <param name="chunkSize">the size, in bytes, of the stream chunks to process at a time</param>
        /// <param name="timeOut">the number of seconds to wait for the function to timeout</param>
        /// <param name="callback">a function called every 'chunkSize' bytes transferred to report status</param>
        /// <param name="cts">a cancellation token for cancelling the request</param>
        /// <param name="resumeToken">Output, a token to resume the file if the upload was interrupted</param>
        /// <param name="retCode">Output, the result code (e.g. 200, 400, etc)</param>
        /// <param name="fileId">Output, the Vault File ID</param>
        /// <param name="fileAliasId">Output, the Vault File Alias ID</param>
        /// <returns>Dictionary<string, object> of values</returns>
        /// <exception cref="Exception"></exception>
        /// <exception cref="ArgumentException"></exception>
        public Dictionary<string, object> putFileStream(string fileNameIn, Dictionary<string, object> srcIdentifier, int chunkSize, int timeOut, Action<ulong, ulong, string> callback, System.Threading.CancellationTokenSource cts, out string resumeToken, out int retCode, out UInt64 fileId, out UInt64 fileAliasId)
        {
            string apiResult = "";

            retCode = 0;
            fileId = 0; fileAliasId = 0;
            Dictionary<string, object> retVal = null;

            System.IO.FileInfo fInfo = new System.IO.FileInfo(fileNameIn);
            if (!fInfo.Exists)
            {
                throw new Exception("Incorrect Input File Path or File Does Not Exist");
            }

            bool resumeUpload = false;
            if (srcIdentifier.TryGetValue("resumetoken", out object objResumeToken))
            {
                // The resumetoken was provided in the request parameters, use it to resume the upload
                resumeToken = "";
                if (objResumeToken != null)
                {
                    resumeToken = objResumeToken.ToString();
                }
                resumeUpload = true;
            }
            else
            {
                // Generate a temp name for the server to store the file. This prevents files of the same name from confilicting with each other.
                // This becomes the token for resuming uploads
                //const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                //Random random = new Random();
                //resumeToken = new string(Enumerable.Repeat(chars, 24)
                //  .Select(s => s[random.Next(s.Length)]).ToArray());
                //resumeToken += fInfo.Extension;        // Add file extension
                resumeToken = System.Guid.NewGuid().ToString().Replace("-", String.Empty);
            }

            // If the destFileName isn't present - add it - this will prevent the backend from using the $_FILES array for the filename which may have different formats for unicode strings
            if (!srcIdentifier.TryGetValue("destFileName", out object tDestFileName))
            {
                srcIdentifier.Add("destFileName", System.IO.Path.GetFileName(fileNameIn));
            }

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/writestream";
            if (!this.validateParams("write")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendFileRequestStream(fileNameIn, chunkSize, timeOut, callback, cts, resumeToken, resumeUpload).Result;
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                object fileAliasIdObj;
                object fileIdObj;
                retVal.TryGetValue("fileAliasId", out fileAliasIdObj);
                retVal.TryGetValue("fileId", out fileIdObj);
                if (fileAliasIdObj != null)
                {
                    fileAliasId = Convert.ToUInt64(fileAliasIdObj.ToString());
                }
                if (fileIdObj != null)
                {
                    fileId = Convert.ToUInt64(fileIdObj.ToString());
                }
            }
            else if (retCode == -1)
            {
                // Custom error message is in apiResult
                throw new Exception(apiResult);
            }
            else
            {
                GetError(retVal, out retCode, out string msg, out string extMsg);
                if (this.verbosity)
                {
                    Console.WriteLine("- Error Occurred putFileStream, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }
            return retVal;
        }

        // Function gets the byte offset to resume a writechunked file upload
        public string GetResumeIndex(Dictionary<string, object> srcIdentifier, out int retCode, out UInt64 resumeIndex)
        {
            string apiResult = "";
            retCode = 0; resumeIndex = 0;

            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/resumeindex";

            if (!this.validateParams("resumeindex")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                resumeIndex = retVal.TryGetValue("index", out object objIndex) ? Convert.ToUInt64(objIndex.ToString()) : 0;
            }

            if (retCode != 200 && this.verbosity)
            {
                GetError(apiResult, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred resumeIndex, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;           
        }

        // Function copies a file in the Vault, creating an entirely new copy, including new files in the storage location(s)
        public Dictionary<string, object> copyFile(Dictionary<string, object> srcIdentifier, Dictionary<string, object> dstIdentifier, out int retCode, out UInt64 fileAliasId)
        {
            string apiResult = "";
            retCode = 0;
            fileAliasId = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = Dictionaries_merge(srcIdentifier, dstIdentifier);
            this.url = this.BASE_API_URL + "api2/file/copy";

            if (!this.validateParams("copy")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                fileAliasId = (retVal.TryGetValue("fileAliasId", out object objFileAliasId) ? Convert.ToUInt64(objFileAliasId.ToString()) : 0);
            }
            else
            {
                GetError(retVal, out retCode, out string msg, out string extMsg);
                if (this.verbosity)
                {
                    Console.WriteLine("- Error Occurred copyFile, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }

            return retVal;
        }

        // Function renames a file in the Vault
        public Dictionary<string, object> renameFile(Dictionary<string, object> srcIdentifier, Dictionary<string, object> dstIdentifier, out int retCode, out UInt64 fileAliasId)
        {
            string apiResult = "";
            retCode = 0;
            fileAliasId = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = Dictionaries_merge(srcIdentifier, dstIdentifier);
            this.url = this.BASE_API_URL + "api2/file/rename";

            if (!this.validateParams("rename")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                fileAliasId = (retVal.TryGetValue("fileAliasId", out object objFileAliasId) ? Convert.ToUInt64(objFileAliasId.ToString()) : 0);
            }
            else
            {
                GetError(retVal, out retCode, out string msg, out string extMsg);
                if (this.verbosity)
                {
                    Console.WriteLine("- Error Occurred renameFile, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }
            return retVal;
        }

        // Function moves a file in the Vault, it does not change the files in the storage location(s)
        public Dictionary<string, object> moveFile(Dictionary<string, object> srcIdentifier, Dictionary<string, object> dstIdentifier, out int retCode, out UInt64 fileAliasId)
        {
            string apiResult = "";
            retCode = 0;
            fileAliasId = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = Dictionaries_merge(srcIdentifier, dstIdentifier);
            this.url = this.BASE_API_URL + "api2/file/move";

            if (!this.validateParams("move")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                fileAliasId = (retVal.TryGetValue("fileAliasId", out object objFileAliasId) ? Convert.ToUInt64(objFileAliasId.ToString()) : 0);
            }
            else
            {
                GetError(retVal, out retCode, out string msg, out string extMsg);
                if (this.verbosity)
                {
                    Console.WriteLine("- Error Occurred moveFile, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }
            return retVal;
        }

        // Function deletes a file in the Vault
        public Dictionary<string, object> deleteFile(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/delete";

            if (!this.validateParams("delete")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out retCode, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred deleteFile, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }
            return retVal;
        }

        // Lists the files and folders in the user's Vault, or in a specified folder in the vault
        public string listAll(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/listall";

            if (!this.validateParams("listall")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred listAll, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;
        }

        // Lists the files in the user's Vault, or in a specified folder in the vault
        public string listFiles(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/listfiles";

            if (!this.validateParams("listfiles")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(apiResult, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred listFiles, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;
        }

        // Lists the files in the specified SmartFolder
        public string listSFFiles(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/listsffiles";

            if (!this.validateParams("listsffiles")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(apiResult, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred listFiles, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;
        }

        // Lists the Folders in the user's Vault
        public string listFolders(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/listfolders";

            if (!this.validateParams("listfolders")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(apiResult, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred listFolders, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;
        }

        // Gets the internal ID for a folder in the user's Vault
        public Dictionary<string, object> getFolderId(Dictionary<string, object> srcIdentifier, out int retCode, out UInt64 dirId)
        {
            Dictionary<string, object> retVal = null;
            string apiResult = "";
            retCode = 0; dirId = 0;
            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/getfolderid";
            if (!this.validateParams("getfolderid")) { throw new ArgumentException("Invalid Input Parameters"); }
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                dirId = (retVal.TryGetValue("folderId", out object objFolderId) ? Convert.ToUInt64(objFolderId.ToString()) : 0);
            }
            else if (this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred getFolderId, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        // Function sets the lock on a file in the Vault
        public Dictionary<string, object> setFileLock(Dictionary<string, object> srcIdentifier, out int retCode, out UInt64 fileAliasId)
        {
            string apiResult = "";
            retCode = 0;
            fileAliasId = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/setfilelock";

            if (!this.validateParams("setfilelock")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                fileAliasId = (retVal.TryGetValue("fileAliasId", out object objFileAliasId) ? Convert.ToUInt64(objFileAliasId.ToString()) : 0);
            }
            else
            {
                if (this.verbosity)
                {
                    GetError(retVal, out retCode, out string msg, out string extMsg);
                    Console.WriteLine("- Error Occurred setFileLock, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }
            return retVal;
        }

        // Function gets the lock state on a file in the Vault
        public Dictionary<string, object> getFileLock(Dictionary<string, object> srcIdentifier, out int retCode, out int fileLock)
        {
            string apiResult = "";
            retCode = 0;
            fileLock = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/getfilelock";

            if (!this.validateParams("getfilelock")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                fileLock = (retVal.TryGetValue("fileLock", out object objFileLock) ? Convert.ToInt16(objFileLock.ToString()) : 0);
            }
            else
            {
                if (this.verbosity)
                {
                    GetError(retVal, out retCode, out string msg, out string extMsg);
                    Console.WriteLine("- Error Occurred getFileLock, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }
            return retVal;
        }

        // Function clears the lock on a file in the Vault
        public Dictionary<string, object> clearFileLock(Dictionary<string, object> srcIdentifier, out int retCode, out UInt64 fileAliasId)
        {
            string apiResult = "";
            retCode = 0;
            fileAliasId = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/clearfilelock";

            if (!this.validateParams("clearfilelock")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                fileAliasId = (retVal.TryGetValue("fileAliasId", out object objFileAliasId) ? Convert.ToUInt64(objFileAliasId.ToString()) : 0);
            }
            else
            {
                if (this.verbosity)
                {
                    GetError(retVal, out retCode, out string msg, out string extMsg);
                    Console.WriteLine("- Error Occurred clearFileLock, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }
            return retVal;
        }

        // Function gets tags on a file in the Vault
        public Dictionary<string, object> getTags(Dictionary<string, object> srcIdentifier, out int retCode, out string strTags)
        {
            string apiResult = "";
            retCode = 0;
            strTags = "";
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/gettags";

            if (!this.validateParams("gettags")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                strTags = (retVal.TryGetValue("fileTags", out object objFileTags) ? objFileTags.ToString() : "");
            }
            else
            {
                if (this.verbosity)
                {
                    GetError(retVal, out retCode, out string msg, out string extMsg);
                    Console.WriteLine("- Error Occurred getTags, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }
            return retVal;
        }

        // Function sets the tags on a file in the Vault
        public Dictionary<string, object> setTags(Dictionary<string, object> srcIdentifier, out int retCode, out UInt64 fileAliasId)
        {
            string apiResult = "";
            retCode = 0;
            fileAliasId = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/settags";

            if (!this.validateParams("settags")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                fileAliasId = (retVal.TryGetValue("fileAliasId", out object objFileAliasId) ? Convert.ToUInt64(objFileAliasId.ToString()) : 0);
            }
            else
            {
                if (this.verbosity)
                {
                    GetError(retVal, out retCode, out string msg, out string extMsg);
                    Console.WriteLine("- Error Occurred clearFileLock, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }
            return retVal;
        }

        // Function adds a tag on a file in the Vault
        public Dictionary<string, object> addTag(Dictionary<string, object> srcIdentifier, out int retCode, out UInt64 fileAliasId)
        {
            string apiResult = "";
            retCode = 0;
            fileAliasId = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/addtag";

            if (!this.validateParams("addtag")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                fileAliasId = (retVal.TryGetValue("fileAliasId", out object objFileAliasId) ? Convert.ToUInt64(objFileAliasId.ToString()) : 0);
            }
            else
            {
                if (this.verbosity)
                {
                    GetError(retVal, out retCode, out string msg, out string extMsg);
                    Console.WriteLine("- Error Occurred addTag, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }
            return retVal;
        }

        // Function deletes a tag on a file in the Vault
        public Dictionary<string, object> deleteTag(Dictionary<string, object> srcIdentifier, out int retCode, out UInt64 fileAliasId)
        {
            string apiResult = "";
            retCode = 0;
            fileAliasId = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/deletetag";

            if (!this.validateParams("deletetag")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                fileAliasId = (retVal.TryGetValue("fileAliasId", out object objFileAliasId) ? Convert.ToUInt64(objFileAliasId.ToString()) : 0);
            }
            else
            {
                if (this.verbosity)
                {
                    GetError(retVal, out retCode, out string msg, out string extMsg);
                    Console.WriteLine("- Error Occurred deleteTag, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }
            return retVal;
        }

        // Creates the specified directory in the user's vault
        public Dictionary<string, object> createDirectory(Dictionary<string, object> srcIdentifier, out int retCode, out UInt64 dirId)
        {
            Dictionary<string, object> retVal = null;
            string apiResult = "";
            retCode = 0; dirId = 0;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/createdirectory";
            if (!this.validateParams("createdirectory")) { throw new ArgumentException("Invalid Input Parameters"); }
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                dirId = (retVal.TryGetValue("folderId", out object objFolderId) ? Convert.ToUInt64(objFolderId.ToString()) : 0);
            }
            else if (this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred Creating Directory, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        public Dictionary<string, object> renameDirectory(Dictionary<string, object> srcIdentifier, Dictionary<string, object> dstIdentifier, out int retCode, out UInt64 dirId)
        {
            Dictionary<string, object> retVal = null;
            string apiResult = "";
            retCode = 0; dirId = 0;

            this.dParams = Dictionaries_merge(srcIdentifier, dstIdentifier);
            this.url = this.BASE_API_URL + "api2/file/renamedirectory";
            if (!this.validateParams("renamedirectory")) { throw new ArgumentException("Invalid Input Parameters"); }
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                dirId = (retVal.TryGetValue("folderId", out object objFolderId) ? Convert.ToUInt64(objFolderId.ToString()) : 0);
            }
            else if (this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred Renaming Directory, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        public Dictionary<string, object> moveDirectory(Dictionary<string, object> srcIdentifier, Dictionary<string, object> dstIdentifier, out int retCode, out UInt64 dirId)
        {
            Dictionary<string, object> retVal = null;
            string apiResult = "";
            retCode = 0; dirId = 0;

            this.dParams = Dictionaries_merge(srcIdentifier, dstIdentifier);
            this.url = this.BASE_API_URL + "api2/file/movedirectory";
            if (!this.validateParams("movedirectory")) { throw new ArgumentException("Invalid Input Parameters"); }
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                dirId = (retVal.TryGetValue("folderId", out object objFolderId) ? Convert.ToUInt64(objFolderId.ToString()) : 0);
            }
            else if (this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred Moving Directory, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        // Copies a directory
        public Dictionary<string, object> copyDirectory(Dictionary<string, object> srcIdentifier, Dictionary<string, object> dstIdentifier, out int retCode, out UInt64 dirId)
        {
            Dictionary<string, object> retVal = null;
            string apiResult = "";
            retCode = 0; dirId = 0;

            this.dParams = Dictionaries_merge(srcIdentifier, dstIdentifier);
            this.url = this.BASE_API_URL + "api2/file/copydirectory";
            if (!this.validateParams("copydirectory")) { throw new ArgumentException("Invalid Input Parameters"); }
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                dirId = (retVal.TryGetValue("folderId", out object objFolderId) ? Convert.ToUInt64(objFolderId.ToString()) : 0);
            }
            else if (this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred Copying Directory, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        // Deletes the specified directory in the user's vault
        public Dictionary<string, object> deleteDirectory(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            Dictionary<string, object> retVal = null;
            string apiResult = "";
            retCode = 0;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/deletedirectory";
            if (!this.validateParams("deletedirectory")) { throw new ArgumentException("Invalid Input Parameters"); }
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred Deleting Directory, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        // Gets information for the specified file in the user's vault
        public string getFileInfo(Dictionary<string, object> srcIdentifier, out int retCode, out string fileName, out UInt64 fileSize, out UInt64 fileTimestamp, out ulong fileAliasId)
        {
            string apiResult = ""; retCode = 0; fileName = ""; fileSize = 0; fileTimestamp = 0; fileAliasId = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/getfileinfo";
            if (!this.validateParams("getfileinfo")) { throw new ArgumentException("Invalid Input Parameters"); }
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                using (JsonDocument apiResponse = JsonDocument.Parse(apiResult))
                {
                    JsonElement fileInfo = apiResponse.RootElement.GetProperty("fileInfo");
                    fileName = (fileInfo.TryGetProperty("fileName", out JsonElement fileNameElement) ? fileNameElement.GetString() : "");
                    fileSize = (fileInfo.TryGetProperty("fileSize", out JsonElement fileSizeElement) ? Convert.ToUInt64(fileSizeElement.GetString()) : 0);
                    fileTimestamp = (fileInfo.TryGetProperty("fileTimestamp", out JsonElement fileTimestampElement) ? fileTimestampElement.GetUInt64() : 0);
                    fileAliasId = (fileInfo.TryGetProperty("fileAliasId", out JsonElement fileAliasIdElement) ? fileAliasIdElement.GetUInt64() : 0);
                }
            }
            else if (this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred GetFileInfo, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;
        }

        // Gets information for the specified folder in the user's vault
        public string getFolderInfo(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/getfolderinfo";
            if (!this.validateParams("getfolderinfo")) { throw new ArgumentException("Invalid Input Parameters"); }
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            return apiResult;
        }

        // Gets sync information for the specified folder in the user's vault
        public Dictionary<string, object> getSyncInfo(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = ""; retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/getsyncinfo";
            if (!this.validateParams("getsyncinfo")) { throw new ArgumentException("Invalid Input Parameters"); }
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && retCode != 404 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred GetSyncInfo, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        // Gets information for the user's vault
        public Dictionary<string, object> getVaultInfo(out int retCode)
        {
            string apiResult = ""; retCode = 0;
            Dictionary<string, object> retVal = null;

            this.url = this.BASE_API_URL + "api2/file/getvaultinfo";
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred GetVaultInfo, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        /**
        * Function checks the provided credentials to make sure the API ID, API PW, username, and account password match a valid account
        * This function generates a failed login if the credentials are not valid for the given user account.
        *
        * @param Array, an associative array containing the source identifier, the values of which credentials to check
        * @return Array, the result / output of the operation
       */
        public Dictionary<string, object> checkCreds(Dictionary<string, object> srcIdentifier, out int retCode, out string errMsg)
        {
            string apiResult = ""; retCode = 0; errMsg = "";
            Dictionary<string, object> retVal = null;
            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/auth/checkcreds";

            if (!this.validateParams("checkcreds")) { throw new ArgumentException("Invalid Input Parameters"); }
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                errMsg = msg + ": " + extMsg;
                if (this.verbosity)
                {
                    Console.WriteLine("- Error Occurred checkCreds, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }

            return retVal;
        }

        /**
        * Function checks the provided credentials to make sure the API ID, API PW, username, and account password match a valid account
        * This function generates a failed login if the credentials are not valid for the given user account.
        *
        * @param Array, an associative array containing the source identifier, the values of which credentials to check
        * @return Array, the result / output of the operation
       */
        public Dictionary<string, object> checkCredsAD(Dictionary<string, object> srcIdentifier, out int retCode, out string errMsg)
        {
            string apiResult = ""; retCode = 0; errMsg = "";
            Dictionary<string, object> retVal = null;
            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/auth/adauth";

            if (!this.validateParams("checkcredsad")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                errMsg = msg + ": " + extMsg;
                if (this.verbosity)
                {
                    Console.WriteLine("- Error Occurred checkCredsAD, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }

            return retVal;
        }

        // Function checks the connection to the Vault
        // Function performs a check with the current API settings to see if it can connect to the Vault
        public bool CheckVaultConnection(out int retCode, out string errMsg)
        {
            errMsg = "";
            string apiResult = ""; retCode = 0;
            Dictionary<string, object> retVal = null;

            this.url = this.BASE_API_URL + "api2/file/testloopback";

            if (!this.validateParams("none")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();

            if (null != this.dParams) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                // No data to return
            }
            else
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                errMsg = msg + ": " + extMsg;
                if (this.verbosity)
                {
                    Console.WriteLine("- Error Occurred _registerSyncClient, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }

            return true;
        }


        /**
          * Function checks the provided username and reports if its taken or not
          *
          * @param Array, an associative array containing the source identifier, the values of which user account to check
          * @return Array, the result / output of the operation
         */
        public Dictionary<string, object> isValidUser(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = ""; retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/auth/isvaliduser";

            if (!this.validateParams("isvaliduser")) { throw new ArgumentException("Invalid Input Parameters"); }
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200)
            {
                if (this.verbosity)
                {
                    GetError(retVal, out int code, out string msg, out string extMsg);
                    Console.WriteLine("- Error Occurred isValidUser, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }
            return retVal;
        }

        /**
          * Function returns the User ID for the given user making the request
          * The API_ID and accountUsername parameters in the request must match the API_ID and username for the user
          * @param Array, an associative array containing the source identifier, the values of which user account to check
          * @return Array, the result / output of the operation
         */
        public Dictionary<string, object> getUserId(Dictionary<string, object> srcIdentifier, out int retCode, out ulong userId)
        {
            string apiResult = ""; retCode = 0; userId = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/auth/getuserid";

            if (!this.validateParams("getuserid")) { throw new ArgumentException("Invalid Input Parameters"); }
            apiResult = this.SendRequest();

            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200)
            {
                if (this.verbosity)
                {
                    GetError(retVal, out int code, out string msg, out string extMsg);
                    Console.WriteLine("- Error Occurred getUserId, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            } else
            {
                if (retVal.TryGetValue("userId", out object objUId) && objUId != null)
                {
                    userId = Convert.ToUInt64(objUId.ToString());
                }
            }

            return retVal;
        }

        /// <summary>
        /// Gets a secret via Diffie-Hellman key agreement to use in encrypting values sent to the server
        /// </summary>
        /// <param name="srcIdentifier">Dictionary<string,object>, the input values (e.g. accountUsername) for the request</param>
        /// <param name="retCode">int, output, the return code from the API call</param>
        /// <param name="pubKey">string, output, the public key used to initiate the DH key agreement on the server</param>
        /// <param name="privKey">string, output, the private key to be used for the DH key agreement calculation on the client</param>
        /// <param name="dhId">string, output, the ID used to identify the DH key agreement params on the server</param>
        /// <param name="serverPubKey">string, output, the server's public key to be used for the DH key agreement calculation on the client</param>
        /// <returns>string, a json encoded string containing 'id' and 'pubkey' to use in API requests</returns>
        /// <exception cref="ArgumentException">for errors in input parameters</exception>
        public string getSecret(Dictionary<string, object> srcIdentifier, out int retCode, out string dhId, out string serverPubKey)
        {
            string apiResult = ""; dhId = ""; serverPubKey = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/auth/getsecret";

            if (!this.validateParams("getsecret")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                // parse out dhId and serverPubKey
                using (JsonDocument apiResponse = JsonDocument.Parse(apiResult))
                {
                    JsonElement secretOutput = apiResponse.RootElement.GetProperty("secret");
                    dhId = (secretOutput.TryGetProperty("id", out JsonElement idElement) ? idElement.GetString() : "");
                    serverPubKey = (secretOutput.TryGetProperty("pubkey", out JsonElement pubKeyElement) ? Encoding.UTF8.GetString(Convert.FromBase64String(pubKeyElement.GetString())) : "");
                }
            }
            else if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred GetSecret, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;
        }

        /// <summary>
        /// Gets a user's API credentials (API_ID and API_PW)
        /// </summary>
        /// <param name="srcIdentifier">Dictionary<string,object>, the input values (e.g. accountUsername) for the request</param>
        /// <param name="retCode">int, output, the return code from the API call</param>
        /// <returns>string, a json encoded string containing 'api_id' and 'api_pw' to use in API requests</returns>
        /// <exception cref="ArgumentException">for errors in input parameters</exception>
        public string getApiCreds(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/auth/getapicreds";

            if (!this.validateParams("getapicreds")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred GetApiCreds, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;
        }

        // Function sets the access permissions for a specified folder
        public Dictionary<string, object> setPermissions(Dictionary<string, object> srcIdentifier, out int retCode, out string[] permIds)
        {
            string apiResult = "";
            retCode = 0;
            permIds = null;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/setperms";

            if (!this.validateParams("setperms")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                object objPermIds;
                retVal.TryGetValue("permIds", out objPermIds);
                if (objPermIds != null)
                {
                    Array tArray = (Array)objPermIds;
                    permIds = new string[tArray.Length];
                    for (int i = 0; i < Convert.ToInt32(tArray.Length.ToString()); i++)
                    {
                        permIds[i] = tArray.GetValue(i).ToString();
                    }
                }
            }
            else if (this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred setPermissions, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        // Function checks the access permissions for a specified folder, user, and requested access level
        public Dictionary<string, object> checkPermissions(Dictionary<string, object> srcIdentifier, out int retCode, out bool result)
        {
            string apiResult = "";
            retCode = 0;
            result = false;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/checkperms";

            if (!this.validateParams("checkperms")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                object objResult;
                retVal.TryGetValue("result", out objResult);
                if (objResult != null)
                {
                    if (objResult.ToString() == "" || objResult.ToString() == "0" || objResult.ToString() == "false")
                    {
                        result = false;
                    }
                    else
                    {
                        result = true;
                    }
                }
            }
            else if (this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred checkPermissions, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        // Function gets the lists of versions for a specified file
        // Returns the JSON encoded response string to make it easier to parse by API caller
        public string listVersions(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/listversions";

            if (!this.validateParams("listversions")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred ListVersions, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;
        }

        // Function reads (gets) a specific version of a file
        // Returns the JSON encoded response string to make it easier to parse by API caller
        public string readVersion(Dictionary<string, object> srcIdentifier, string fileNameOut, ulong fileSize, int timeOut, Action<ulong, ulong, string> callback, CancellationTokenSource cts, out int retCode)
        {
            string apiResult = "";
            retCode = 0;

            //this.getFile();

            if (fileNameOut == null || fileNameOut == "")
            {
                throw new ArgumentException("An Output File Name Must be Specified");
            }

            // Check fileNameOut contains a valid path
            System.IO.FileInfo fInfo = new System.IO.FileInfo(fileNameOut);
            if (!fInfo.Directory.Exists)
            {
                throw new Exception("Incorrect Output File Path or Path Does Not Exist");
            }

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/readversion";

            if (!this.validateParams("readversion")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.sendDownloadRequest(fileNameOut, fileSize, timeOut, callback, cts, out retCode);
            if (this.dParams != null) { this.dParams.Clear(); }

            if (apiResult == "1")
            {   // Simulate a 200 OK if command succeeds
                retCode = 200;
                Dictionary<string, object> retVal = new Dictionary<string, object>();
                retVal.Add("code", 200);
                retVal.Add("message", "OK");
                retVal.Add("fileName", fileNameOut);
                //apiResult = JsonSerializer.Serialize(retVal);
                apiResult = Newtonsoft.Json.JsonConvert.SerializeObject(retVal);
            }
            return apiResult;
        }

        // Function restores a specific version of a file to the current / master file
        // Returns the JSON encoded response string to make it easier to parse by API caller
        public string restoreVersion(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/restoreversion";

            if (!this.validateParams("restoreversion")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred restoreVersion, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;
        }

        // Function deletes a specific version of a file
        // Returns the JSON encoded response string to make it easier to parse by API caller
        public string deleteVersion(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/deleteversion";

            if (!this.validateParams("deleteversion")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred deleteVersion, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;
        }

        // Function gets the parameters sent by the client and returned / echo'd by the server
        // Returns the JSON encoded response string to make it easier to parse by API caller
        public string testLoopback(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/testloopback";

            if (!this.validateParams("none")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred TestLoopback, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;
        }

        // Uploads file to the user's Vault
        public Dictionary<string, object> webEraseUpdate(string fileNameIn, Dictionary<string, object> srcIdentifier, int timeOut, out int retCode, out UInt64 fileId, out UInt64 fileAliasId)
        {
            string apiResult = "";
            retCode = 0;
            fileId = 0; fileAliasId = 0;
            Dictionary<string, object> retVal = null;

            System.IO.FileInfo fInfo = new System.IO.FileInfo(fileNameIn);
            if (!fInfo.Exists)
            {
                throw new Exception("Incorrect Input File Path or File Does Not Exist");
            }

            this.url = this.BASE_API_URL + "api2/weberase/update";
            this.dParams = srcIdentifier;
            if (!this.validateParams("weberaseupdate")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendFileRequest(fileNameIn, timeOut);
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                fileAliasId = (retVal.TryGetValue("fileAliasId", out object objFileAliasId) ? Convert.ToUInt64(objFileAliasId.ToString()) : 0);
                fileId = (retVal.TryGetValue("fileId", out object objFileId) ? Convert.ToUInt64(objFileId.ToString()) : 0);
            }
            else
            {
                if (this.verbosity)
                {
                    GetError(retVal, out retCode, out string msg, out string extMsg);
                    Console.WriteLine("- Error Occurred WebErase Update, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }

            return retVal;
        }

        // Function gets a new token for a WebErase store operation
        public Dictionary<string, object> webEraseToken(Dictionary<string, object> srcIdentifier, out int retCode, out string token)
        {
            string apiResult = "";
            retCode = 0;
            token = "";
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/weberase/token";

            if (!this.validateParams("weberasetoken")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                token = (retVal.TryGetValue("token", out object objToken) ? objToken.ToString() : "");
            }
            else if (this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred webEraseToken, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        // Function gets the list of WebErase projects in the account
        // Lists the files and folders in the user's Vault, or in a specified folder in the vault
        // Returns the JSON encoded response string to make it easier to parse by API caller
        public string webEraseProjectList(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/weberase/projectlist";

            if (!this.validateParams("weberaseprojectlist")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred WebErase Project List, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return apiResult;
        }

        // Uploads file to the user's Vault
        public Dictionary<string, object> webEraseStore(string fileNameIn, Dictionary<string, object> srcIdentifier, int timeOut, out int retCode, out UInt64 fileId, out UInt64 fileAliasId, out int oneTimeCode)
        {
            string apiResult = "";
            retCode = 0;
            fileId = 0; fileAliasId = 0; oneTimeCode = 0;
            Dictionary<string, object> retVal = null;

            System.IO.FileInfo fInfo = new System.IO.FileInfo(fileNameIn);
            if (!fInfo.Exists)
            {
                throw new Exception("Incorrect Input File Path or File Does Not Exist");
            }

            this.url = this.BASE_API_URL + "api2/weberase/store";
            this.dParams = srcIdentifier;
            if (!this.validateParams("weberasestore")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendFileRequest(fileNameIn, timeOut);
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                fileAliasId = (retVal.TryGetValue("fileAliasId", out object objFileAliasId) ? Convert.ToUInt64(objFileAliasId.ToString()) : 0);
                fileId = (retVal.TryGetValue("fileId", out object objFileId) ? Convert.ToUInt64(objFileId.ToString()) : 0);
                oneTimeCode = (retVal.TryGetValue("otc", out object objOtc) ? Convert.ToInt32(objOtc.ToString()) : 0);
            }
            else
            {
                if (this.verbosity)
                {
                    GetError(retVal, out retCode, out string msg, out string extMsg);
                    Console.WriteLine("- Error Occurred WebErase Store, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }

            return retVal;
        }

        // Downloads a file from the user's vault or polls for a file pending transaction validation
        private Dictionary<string, object> webEraseDownload(Dictionary<string, object> srcIdentifier, string fileNameOut, int timeOut, bool polling, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = new Dictionary<string, object>();

            // Check fileNameOut contains a valid path
            System.IO.FileInfo fInfo = new System.IO.FileInfo(fileNameOut);
            if (!fInfo.Directory.Exists)
            {
                throw new Exception("Incorrect Output File Path or Path Does Not Exist");
            }

            this.dParams = srcIdentifier;
            if (polling)
            {
                this.url = this.BASE_API_URL + "api2/weberase/polling";
            }
            else
            {
                this.url = this.BASE_API_URL + "api2/weberase/retrieve";
            }
            // Params are validated the same for retrieve and polling
            if (!this.validateParams("weberaseretrieve")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.sendDownloadRequest(fileNameOut, 0, timeOut, null, null, out retCode);
            if (this.dParams != null) { this.dParams.Clear(); }

            if (apiResult == "1")
            {   // Simulate a 200 OK if command succeeds
                retCode = 200;
                retVal.Add("code", "200");
                retVal.Add("message", "OK");
                retVal.Add("fileName", fileNameOut);
            }
            else
            {
                // Something else went wrong with the request
                // Try to deserialize the response
                try
                {
                    object objCheckDict = JsonSerializer.Deserialize(apiResult, typeof(object));
                    return (Dictionary<string, object>)objCheckDict;
                }
                catch (Exception ex)
                {
                    retCode = -1;
                    retVal.Add("code", -1);
                    retVal.Add("message", "Unable to Download File - " + ex.Message + " - " + apiResult);
                }
            }
            return retVal;
        }

        // Downloads a file from the user's vault
        public Dictionary<string, object> webEraseRetrieve(Dictionary<string, object> srcIdentifier, string fileNameOut, int timeOut, out int retCode)
        {
            retCode = 0;
            return webEraseDownload(srcIdentifier, fileNameOut, timeOut, false, out retCode);
        }

        // Polls and downloads a file pending transaction validation
        public Dictionary<string, object> webErasePolling(Dictionary<string, object> srcIdentifier, string fileNameOut, int timeOut, out int retCode)
        {
            retCode = 0;
            return webEraseDownload(srcIdentifier, fileNameOut, timeOut, true, out retCode);
        }

        // Function deletes the file specified by the token
        public Dictionary<string, object> webEraseDelete(Dictionary<string, object> srcIdentifier, out int retCode)
        {
            string apiResult = "";
            retCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/weberase/delete";

            if (!this.validateParams("weberasedelete")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred WebErase Delete, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        // Function requests the one time code assigned to the token
        public Dictionary<string, object> webEraseOneTimeCode(Dictionary<string, object> srcIdentifier, out int retCode, out int oneTimeCode)
        {
            string apiResult = "";
            retCode = 0; oneTimeCode = 0;
            Dictionary<string, object> retVal = null;

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/weberase/onetimecode";

            if (!this.validateParams("weberaseotc")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendRequest();
            if (this.dParams != null) { this.dParams.Clear(); }

            retCode = GetResponseCodeDict(apiResult, out retVal);

            if (retCode == 200)
            {
                oneTimeCode = (retVal.TryGetValue("otc_code", out object objOtc) ? Convert.ToInt32(objOtc.ToString()) : 0);
            }
            else if (retCode != 200 && this.verbosity)
            {
                GetError(retVal, out int code, out string msg, out string extMsg);
                Console.WriteLine("- Error Occurred WebErase Delete, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
            }

            return retVal;
        }

        // Parses the string returned from the API call to get the code and a Dictionary<> with all the return values
        public static int GetResponseCodeDict(string apiResult, out Dictionary<string, object> retVal)
        {
            int retCode = -1; retVal = null;

            try
            {
                retVal = JsonSerializer.Deserialize<Dictionary<string, object>>(apiResult);

                // Get return code from the result
                object tCode;
                if (retVal.TryGetValue("code", out tCode))
                {
                    retCode = Convert.ToInt32(tCode.ToString());
                }
                else
                {
                    retCode = -1;
                }
            }
            catch (Exception ex)
            {
                retCode = -1;
                Console.WriteLine("ERROR - STASHAPI:GetErrorCode(): " + ex.Message);
            }
            return retCode;
        }

        // Parses the return Dictionary<> to get the error code, message, and extended message
        public static void GetError(Dictionary<string, object> responseIn, out int code, out string msg, out string extMsg)
        {
            code = 0; msg = ""; extMsg = "";
            //object val1 = null; object val2 = null; object val3 = null;

            if (responseIn == null) { code = -1; msg = "Response was Null"; extMsg = ""; return; }

            if (responseIn.TryGetValue("code", out object je1)) {
                code = (((JsonElement)je1).TryGetInt32(out code) ? code : 0);
            }

            if (responseIn.TryGetValue("message", out object je2)) {
                msg = ((JsonElement)je2).ToString();
            }

            if (responseIn.TryGetValue("error", out object extError))
            {
                string tStr = ((JsonElement)extError).ToString();
                ExtendedError extErr = JsonSerializer.Deserialize<ExtendedError>(tStr);
                extMsg = extErr.extendedErrorMessage;
            }
        }

        // Parses the return string result (JSON-encoded string) to get the error code, message, and extended message
        public static void GetError(string responseIn, out int code, out string msg, out string extMsg)
        {
            code = 0; msg = ""; extMsg = "";
            try
            {
                if (responseIn == null || responseIn == "") { throw new Exception("Empty API Error Response"); }

                apiError apiErr = JsonSerializer.Deserialize<apiError>(responseIn);
                code = apiErr.code;
                msg = apiErr.message;
                extMsg = apiErr.error.extendedErrorMessage;
            } catch (Exception ex)
            {
                code = -1;
                msg = "Error Reading API Error Response: " + ex.Message;
                extMsg = "";
            }
        }


        public static bool IsStringArraysEqual(string[] arr1, string[] arr2)
        {
            int arr1Length = arr1.GetLength(0);
            int arr2Length = arr2.GetLength(0);

            try
            {
                if (arr1Length != arr2Length) { return false; }
                for (int i = 0; i < arr1.GetLength(0); i++)
                {
                    if (arr1[i] != arr2[i]) { return false; }
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR - STASHAPI::IsStringArraysEqual() - Error: " + ex.Message);
                return false;
            }
        }

        // Returns T if the object can be converted to a string that contains only digits (0-9)
        // Returns T for integers only
        public static bool IsNumeric(object valIn)
        {
            if (valIn == null) { return false; }
            string strVal = valIn.ToString();
            foreach (char c in strVal)
            {
                if (!Char.IsDigit(c)) { return false; }
            }
            return true;
        }

        /**
         * Checks if the string is a valid email address
         * @see https://docs.microsoft.com/en-us/dotnet/standard/base-types/how-to-verify-that-strings-are-in-valid-email-format
         */
        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            try
            {
                // Normalize the domain
                email = Regex.Replace(email, @"(@)(.+)$", DomainMapper, RegexOptions.None, TimeSpan.FromMilliseconds(200));

                // Examines the domain part of the email and normalizes it.
                string DomainMapper(Match match)
                {
                    // Use IdnMapping class to convert Unicode domain names.
                    var idn = new IdnMapping();

                    // Pull out and process domain name (throws ArgumentException on invalid)
                    var domainName = idn.GetAscii(match.Groups[2].Value);

                    return match.Groups[1].Value + domainName;
                }
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
            catch (ArgumentException)
            {
                return false;
            }

            try
            {
                return Regex.IsMatch(email,
                    @"^(?("")("".+?(?<!\\)""@)|(([0-9a-z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-z])@))" +
                    @"(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-z][-0-9a-z]*[0-9a-z]*\.)+[a-z0-9][\-a-z0-9]{0,22}[a-z0-9]))$",
                    RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250));
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
        }

        /*
         * Deep copies a dictionary
         * Useful for calling GetResumeIndex() before a writechunked operation to preserve the dictionary passed into SendFileRequestChunked()
         */
        public Dictionary<string, object> CopyDictionary(Dictionary<string, object> dictIn)
        {
            // Copy all keys in the dictionary, but rename "destFileName", "destFolderNames", "destFolderId", "destFilePath"
            Dictionary<string, object> result = new Dictionary<string, object>();

            // Look for dest parameters or source parameters so the conversion works for both destination params, and inadvertent source params specified as destination params
            foreach (KeyValuePair<string, object> keyValue in dictIn)
            {
                if (keyValue.Key == "destFolderNames" || keyValue.Key == "folderNames")
                {
                    // Assume destFolderNames or folderNames is a one-deep string array; copy each value
                    List<string> tList = new List<string>();
                    foreach (string str in (string[])keyValue.Value)
                    {
                        tList.Add(str);
                    }
                    result.Add(keyValue.Key, tList.ToArray());
                }
                else
                {
                    result.Add(keyValue.Key, keyValue.Value.ToString());
                }
            }

            return result;
        }

        /*
         * Converts a destination dictionary to a source dictionary
         * Useful for calling getFileInfo() before a write/writechunked operation to check if the destination exists
         * if allKeys = true, will convert all keys, otherwise will just convert/copy destFileName, destFolderNames, destFolderId, and destFilePath
         */
        public Dictionary<string, object> convertDestinationToSourceDictionary(Dictionary<string, object> destDictIn, bool allKeys)
        {
            // Copy all keys in the dictionary, but rename "destFileName", "destFolderNames", "destFolderId", "destFilePath"
            Dictionary<string, object> result = new Dictionary<string, object>();

            // Look for dest parameters or source parameters so the conversion works for both destination params, and inadvertent source params specified as destination params
            foreach (KeyValuePair<string, object> keyValue in destDictIn)
            {
                if (keyValue.Key == "destFileName" || keyValue.Key == "fileName")
                {
                    result.Add("fileName", keyValue.Value.ToString());
                }
                else if (keyValue.Key == "destFolderNames" || keyValue.Key == "folderNames")
                {
                    // Assume destFolderNames or folderNames is a one-deep string array; copy each value
                    List<string> tList = new List<string>();
                    foreach (string str in (string[])keyValue.Value)
                    {
                        tList.Add(str);
                    }
                    result.Add("folderNames", tList.ToArray());
                }
                else if (keyValue.Key == "destFolderId" || keyValue.Key == "folderId")
                {
                    result.Add("folderId", keyValue.Value.ToString());
                }
                else if (keyValue.Key == "destFilePath" || keyValue.Key == "filePath")
                {
                    result.Add("filePath", keyValue.Value.ToString());
                }
                else
                {
                    if (allKeys)
                    {
                        result.Add(keyValue.Key, keyValue.Value.ToString());
                    }
                }
            }

            return result;
        }

        /**
         * Calculates a SHA1 hash of a file
         * See: https://stackoverflow.com/questions/1993903/how-do-i-do-a-sha1-file-checksum-in-c
         */
        public static string FileSha1Hash(string filePathIn)
        {
            StringBuilder formatted = new StringBuilder("");

            using (FileStream fs = new FileStream(filePathIn, FileMode.Open))
            using (BufferedStream bs = new BufferedStream(fs))
            {
                using (SHA1 sha1 = SHA1.Create())
                {
                    byte[] hash = sha1.ComputeHash(bs);
                    formatted = new StringBuilder(2 * hash.Length);
                    foreach (byte b in hash)
                    {
                        formatted.AppendFormat("{0:X2}", b);
                    }
                }
            }
            return formatted.ToString().ToLower();
        }

        public static string FileSha256Hash(string filePathIn)
        {
            StringBuilder formatted = new StringBuilder("");

            using (FileStream fs = new FileStream(filePathIn, FileMode.Open))
            using (BufferedStream bs = new BufferedStream(fs))
            {
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(bs);
                    formatted = new StringBuilder(2 * hash.Length);
                    foreach (byte b in hash)
                    {
                        formatted.AppendFormat("{0:X2}", b);
                    }
                }
            }
            return formatted.ToString().ToLower();
        }
    }

    public class ExtendedError
    {
        public int errorCode { get; set; }
        public string extendedErrorMessage { get; set; }
    }

    public class apiError
    {
        public int code { get; set; }
        public string message { get; set; }
        public ExtendedError error { get; set; }
    }
}
