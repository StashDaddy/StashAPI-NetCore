/* This is a Visual Studio Shared Project
 * This library requires .NET 5.0+ (formerly .NET Core) due to System.Text.Json instead of System.Web.Script.Serialization.JsonSerializer
 *
 * To use this project, add the project to your existing solution (Add->existing project->stashapi.shproj), then add a reference to the shared
 * project from your existing code/application project (Add->shared project reference->Shared Projects)
 * Structure:
 * - Solution
 * -- Code .net/c#/vb project
 * -- STASHAPI shared project
 * 
 * Important Note - you must add the following references to you code/application project
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

namespace Stash
{
    public class StashAPI : Object
    {
        public const string STASHAPI_VERSION = "1.0";       // API Version
        public const int STASHAPI_ID_LENGTH = 32;        // api_id String length
        public const int STASHAPI_PW_LENGTH = 32;        // API_PW String length (minimum)
        public const int STASHAPI_SIG_LENGTH = 32;       // API_SIGNATURE String length (minimum)
        public const int STASHAPI_FILE_BUFFER_SIZE = 1024;  // Input / Output buffer for reading / writing files
        public const string BASE_VAULT_FOLDER = "My Home";
        public const string BASE_URL = "https://www.stage.stashbusiness.com/";      // This is the URL to send requests to, can be overrided by BASE_API_URL in the constructor
        public const string ENC_ALG = "aes-256-cbc";        // Encryption algorithm for use in encryptString & decryptString(), encryptFile() & decryptFile(), uses an IV of 16 bytes
        public const int STASH_ENC_BLOCKSIZE = 1024;        // The size of the data block to encrypt; must match the blocksize used in the decryption platform - IV.length
        public const int STASH_DEC_BLOCKSIZE = 1040;        // The size of the data block to decrypt; must be STASH_ENC_BLOCKSIZE + IV.length; must match the blocksize used in the encryption platform + IV.length

        private static readonly HttpClient client = new HttpClient();

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

        // STASHAPI.CS Constructor
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

            strToSign = JsonSerializer.Serialize(dataIn);

            sig = Hash_hmac("sha256", strToSign, this.api_pw);

            // Convert to lowercase to match PHP's hash_hmac function which outputs lowercase hexbits
            this.api_signature = sig.ToLower();
            if (this.verbosity) { Console.WriteLine(" - setSignature - strToSign: " + strToSign + " sig: " + sig); }
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

                    ct = EncryptString(pt);
                    wrt.Write(ct);
                }
            }
            return true;
        }

        // Encrypts a String with the API_PW
        public string EncryptString(string strString, bool returnHexBits)
        {
            string retVal = "";
            byte[] tRetVal;

            if (strString == "") { return ""; }
            if (this.api_pw == "") { return ""; }
            if (this.api_pw.Length < 32) { throw new ArgumentException("API_PW must be at least 32 characters"); }

            Aes crypto = Aes.Create();
            crypto.Key = Encoding.ASCII.GetBytes(this.api_pw);
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

        // Encrypts a set of bytes with the API_PW
        public byte[] EncryptString(byte[] strString)
        {
            byte[] retVal;
            byte[] ct;

            if (strString.Length < 1) { throw new ArgumentException("Input Bytes are Empty"); }
            if (this.api_pw == "") { return null; }
            if (this.api_pw.Length < 32) { throw new ArgumentException("API_PW must be at least 32 characters"); }//if (this.api_pw.Length < 32) { throw new ArgumentException("API_PW must be at least 32 characters"); }

            Aes crypto = Aes.Create();
            crypto.Key = Encoding.ASCII.GetBytes(this.api_pw);
            crypto.Mode = CipherMode.CBC;
            crypto.Padding = PaddingMode.PKCS7;

            ICryptoTransform encryptor = crypto.CreateEncryptor(crypto.Key, crypto.IV);
            using (MemoryStream msEncrypt = new MemoryStream(strString))
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Read))
            using (BinaryReader srEncrypt = new BinaryReader(csEncrypt))
            {
                ct = srEncrypt.ReadBytes(1024);
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
            const int STASH_DEC_BLOCKSIZE = 1040;
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
            HttpResponseMessage response = await client.PostAsync(uri, new StringContent(payload, Encoding.UTF8, "application/json"));
            return await response.Content.ReadAsStringAsync();
        }

        /*
         * Posts a string of JSON (payload) to the specified URI and returns a stream for the response (e.g. when downloading a file)
         * See https://www.tugberkugurlu.com/archive/efficiently-streaming-large-http-responses-with-httpclient
         */
        public async Task<Stream> PostURIasStream(string uri, string payload, double timeOutIn, CancellationToken ct)
        {
            client.Timeout = TimeSpan.FromSeconds(timeOutIn);
            HttpResponseMessage response = await client.PostAsync(uri, new StringContent(payload, Encoding.UTF8, "application/json"), ct);
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
            payload = JsonSerializer.Serialize(apiParams);       // apiParams is already merged if need be in signature above
            //byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
           
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
        public string sendDownloadRequest(string fileNameIn, int timeOut)
        {
            string payload = "";

            if (this.verbosity) { Console.WriteLine(" - sendDownloadRequest - "); }
            if (this.url == "") { throw new ArgumentException("Invalid URL"); }
            System.IO.FileStream fileStream = null;
            //WebResponse objResponse = null;
            System.IO.Stream sendStream = null;

            try
            {
                //System.Net.HttpWebRequest objHWR = (HttpWebRequest)WebRequest.Create(this.url);
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
                payload = JsonSerializer.Serialize(apiParams);       // apiParams is already merged if need be in signature above
                                                                     //byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

                //objHWR.Method = WebRequestMethods.Http.Post;
                //objHWR.ContentType = "application/json";
                //objHWR.ContentLength = payloadBytes.LongLength;
                //objHWR.Timeout = timeOut * 1000;

                var t = Task.Run(() => PostURIasStream(this.url, payload, timeOut, new CancellationToken()));
                t.Wait();
                sendStream = t.Result;
                //retVal = t.Result;

                //sendStream = objHWR.GetRequestStream();
                //sendStream.Write(payloadBytes, 0, payloadBytes.Length);
                //sendStream.Close();

                //objResponse = objHWR.GetResponse();
                //sendStream = objResponse.GetResponseStream();

                int bufferSize = STASHAPI_FILE_BUFFER_SIZE;
                byte[] buffer = new byte[bufferSize];
                int bytesRead = sendStream.Read(buffer, 0, buffer.Length);

                // Examine buffer for error JSON and if found, skip the download and return error
                // If any error occurs during this error check, just dump the output to the file anyway
                try
                {
                    string tStr = Encoding.ASCII.GetString(buffer, 0, 200);

                    int idx = tStr.IndexOf('\0');
                    if (idx >= 1)
                    {
                        tStr = tStr.Substring(0, idx);
                        apiError apiErr = JsonSerializer.Deserialize<apiError>(tStr);
                        if (apiErr.code >= 400 && apiErr.code <= 500)
                        {   // The value returned was an API error JSON string, not the file content, return the error JSON
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
                    fileStream.Write(buffer, 0, bytesRead);
                    bytesRead = sendStream.Read(buffer, 0, buffer.Length);
                }
                return "1";
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
            finally
            {
                if (fileStream != null) { fileStream.Close(); }
                if (sendStream != null) { sendStream.Close(); }
                //if (objResponse != null) { objResponse.Close(); }
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
                //double pct = 0;
                //if (fileSize > 0)
                //{
                //    pct = Math.Round((double)processedBytes / (double)fileSize * 100);
                //}
                //if (pct < 0) { pct = 0; }
                //else if (pct > 100) { pct = 100; }
                //string strPct = String.Concat(pct, "%");

                //statusUpdate.Turn("Uploading File... ", " " + strPct + " (" + processedBytes + "/" + fileSize + ")", "Uploading File", "");
            };

            // CancellationTokenSource
            var t = Task.Run(() => this.SendFileRequestChunked(fileNameIn, Convert.ToInt32(fileSize), timeOut, callback, new CancellationTokenSource()));
            t.Wait();
            retVal = t.Result;

            if (this.verbosity)
            {
                Console.WriteLine("- sendFileRequest Complete - Result: " + retVal);
            }
            
            return retVal;

            //string retVal = await this.SendFileRequestChunked(fileNameIn, Convert.ToUInt32(fileSize), timeOut, null, new CancellationTokenSource());
            /*

            if (this.verbosity) { Console.WriteLine(" - sendFileRequest - "); }
            if (this.url == "") { throw new ArgumentException("Invalid URL"); }
            if (fileNameIn == "" || !System.IO.File.Exists(fileNameIn)) { throw new ArgumentException("A Filename Must Be Specified, or File Does Not Exist"); }

            // Build params list containing needed API fields
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

            HttpWebRequest requestToServer = (HttpWebRequest)WebRequest.Create(this.url);

            string boundaryString = "----" + genRandomString(24);
            requestToServer.Timeout = timeOut * 1000;
            requestToServer.AllowWriteStreamBuffering = false;
            requestToServer.Method = WebRequestMethods.Http.Post;
            requestToServer.ContentType = "multipart/form-data; boundary=" + boundaryString;
            requestToServer.KeepAlive = false;

            ASCIIEncoding ascii = new ASCIIEncoding();
            string boundaryStringLine = Environment.NewLine + "--" + boundaryString + Environment.NewLine;
            byte[] boundaryStringLineBytes = ascii.GetBytes(boundaryStringLine);

            string lastBoundaryStringLine = Environment.NewLine + "--" + boundaryString + "--" + Environment.NewLine;
            byte[] lastBoundaryStringLineBytes = ascii.GetBytes(lastBoundaryStringLine);

            string strVals = "";
            foreach (KeyValuePair<string, object> kvp in apiParams)
            {
                //if (IsArray(kvp.Value))
                if (kvp.Value.GetType() == typeof(string[]))
                {
                    strVals = strVals + String.Format("\"{0}\":[", kvp.Key.ToString());
                    foreach (string strItem in (string[])kvp.Value)
                    {
                        strVals = strVals + String.Format("\"{0}\",", strItem);
                    }
                    strVals = strVals.Substring(0, strVals.Length - 1);     // Strip off final comma
                    strVals = strVals + "],";
                }
                else
                {
                    strVals = strVals + String.Format("\"{0}\":\"{1}\",", kvp.Key.ToString(), kvp.Value.ToString());
                }
            }

            if (strVals.Substring(strVals.Length - 1, 1) == ",")       // If last character is a comma
            {
                strVals = strVals.Substring(0, strVals.Length - 1);     // Strip off final comma
            }
            string strParams = String.Format("Content-Disposition: form-data; name=\"{0}\"{2}{2}{{{1}}}", "params", strVals, Environment.NewLine);
            byte[] strParamsBytes = ascii.GetBytes(strParams);
            if (this.verbosity) { Console.WriteLine("strParams: " + strParams); }

            System.IO.FileInfo uploadFile = new System.IO.FileInfo(fileNameIn);
            string strContentType = "application/unknown";      // Receiver will handle the file type, doesn't matter what we put here
            string strFile = String.Format("Content-Disposition: form-data; name=\"file\"; filename=\"{1}\"{3}Content-Type: {2}{3}{3}", uploadFile.Name, uploadFile.Name, strContentType, Environment.NewLine);
            byte[] strFileBytes = ascii.GetBytes(strFile);
            if (this.verbosity) { Console.WriteLine("strFile: " + strFile); }

            // Calculate the total size of the HTTP request
            long totalRequestBodySize = boundaryStringLineBytes.Length * 2 + lastBoundaryStringLineBytes.Length + strParamsBytes.Length + strFileBytes.Length + uploadFile.Length;
            requestToServer.ContentLength = totalRequestBodySize;

            System.IO.Stream s = requestToServer.GetRequestStream();
            s.Write(boundaryStringLineBytes, 0, boundaryStringLineBytes.Length);
            s.Write(strParamsBytes, 0, strParamsBytes.Length);

            s.Write(boundaryStringLineBytes, 0, boundaryStringLineBytes.Length);
            s.Write(strFileBytes, 0, strFileBytes.Length);

            System.IO.FileStream fileStream = new System.IO.FileStream(fileNameIn, System.IO.FileMode.Open, System.IO.FileAccess.Read);
            byte[] buffer = new byte[32768];
            int loopCounter = 0;
            int bytesRead = fileStream.Read(buffer, 0, buffer.Length);
            while (bytesRead != 0)
            {
                s.Write(buffer, 0, bytesRead);
                s.Flush();
                loopCounter++;
                if ((loopCounter % 10) == 0)
                {
                    s.Flush();
                }
                bytesRead = fileStream.Read(buffer, 0, buffer.Length);
            }
            fileStream.Close();

            s.Write(lastBoundaryStringLineBytes, 0, lastBoundaryStringLineBytes.Length);

            WebResponse objResponse = requestToServer.GetResponse();
            System.IO.Stream responseStream = objResponse.GetResponseStream();
            System.IO.StreamReader reader = new System.IO.StreamReader(responseStream);
            retVal = reader.ReadToEnd();
            reader.Close();
            responseStream.Close();
            objResponse.Close();

            if (this.verbosity)
            {
                Console.WriteLine("- sendFileRequest Complete - Result: " + retVal);
            }
            return retVal;
            */
        }

        // Uploads a file to the server in chunks. While the functions are awaited, the chunks are being uploaded to the file synchronously.
        //TODO: Update function to upload chunks asynchronously
        public async Task<string> SendFileRequestChunked(string fileNameIn, int chunkSize, int timeOut, Action<ulong, ulong, string> callback, System.Threading.CancellationTokenSource ct)
        {
            string retVal = "";

            if (this.verbosity) { Console.WriteLine(" - sendFileRequest - "); }
            if (this.url == "") { throw new ArgumentException("Invalid URL"); }
            if (fileNameIn == "" || !System.IO.File.Exists(fileNameIn)) { throw new ArgumentException("A Filename Must Be Specified, or File Does Not Exist"); }
            this.url = this.BASE_API_URL + "api2/file/writechunked";
            // Build params list containing needed API fields

            System.IO.FileInfo uploadFile = new System.IO.FileInfo(fileNameIn);
            Dictionary<string, string> chunkedParams = new Dictionary<string, string>();

            //Generate a temp name for the server to store the file. This prevents files of the same name from confilicting with each other.
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            Random random = new Random();
            string temp_name = new string(Enumerable.Repeat(chars, 24)
              .Select(s => s[random.Next(s.Length)]).ToArray());
            chunkedParams.Add("temp_name", temp_name);

            if (uploadFile.Length < chunkSize)
            {
                chunkSize = Convert.ToInt32(uploadFile.Length);  // if the file is smaller than the chunk size, upload the file as one chunk
            }

            byte[] buffer = new byte[chunkSize];
            FileStream fileStream = null;
            try
            {
                fileStream = new FileStream(fileNameIn, FileMode.Open, FileAccess.Read,
                FileShare.Read, bufferSize: chunkSize, useAsync: true);
                Int32 bytesRead = 0;
                int i = 1;
                var responseString = string.Empty;

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

                string strVals = "";
                foreach (KeyValuePair<string, object> kvp in apiParams)
                {
                    if (kvp.Value.GetType() == typeof(string[]))
                    {
                        strVals = strVals + String.Format("\"{0}\":[", kvp.Key.ToString());
                        foreach (string strItem in (string[])kvp.Value)
                        {
                            strVals = strVals + String.Format("\"{0}\",", strItem);
                        }
                        strVals = strVals.Substring(0, strVals.Length - 1);     // Strip off final comma
                        strVals = strVals + "],";
                    }
                    else
                    {
                        strVals = strVals + String.Format("\"{0}\":\"{1}\",", kvp.Key.ToString(), kvp.Value.ToString());
                    }
                }

                if (strVals.Substring(strVals.Length - 1, 1) == ",")       // If last character is a comma
                {
                    strVals = strVals.Substring(0, strVals.Length - 1);     // Strip off final comma
                }
                // ToDo Replace with callback (see Issue #9, STASHAPI-NET-Dev)
                var stopWatch = System.Diagnostics.Stopwatch.StartNew();

                //Begin reading the file and send each chunk to the server.
                while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    //Check cancellation token. If the user clicks stop, the upload will be aborted.
                    bool isCancelled = ct.IsCancellationRequested;
                    if (isCancelled == true)
                    {
                        break;
                    }
                    else
                    {

                        double chunks = (double)fileStream.Length / (double)chunkSize;
                        var totalChunks = Math.Ceiling(chunks);

                        if (i == 3)
                        {
                            stopWatch.Stop();
                            TimeSpan ts = stopWatch.Elapsed;
                        }
                        if (chunkedParams.ContainsKey("progress"))
                        {
                            chunkedParams.Remove("progress");
                        }

                        if (!chunkedParams.ContainsKey("chunkedUpload"))
                        {
                            chunkedParams.Add("chunkedUpload", "true");
                        }
                        chunkedParams.Add("progress", i + "/" + totalChunks);

                        int pos = fileNameIn.LastIndexOf("\\") + 1;

                        // Update timestamp and signature in apiParams with each chunk
                        // Each chunk MUST be able to be sent in the timeout period set by timestamp
                        this.api_timestamp = 0;        // Set to current timestamp
                        apiParams.Remove("api_timestamp");
                        apiParams.Remove("api_signature");
                        apiParams.Add("api_timestamp", this.api_timestamp);
                        this.setSignature(apiParams);
                        apiParams.Add("api_signature", this.getSignature());
                        
                        var apiParameters = JsonSerializer.Serialize(apiParams);
                        var chunkedParameters = JsonSerializer.Serialize(chunkedParams);
                        ASCIIEncoding ascii = new ASCIIEncoding();
                        ByteArrayContent data = new ByteArrayContent(buffer);
                        data.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("multipart/form-data");
                        byte[] strParamsBytes = ascii.GetBytes(apiParameters);
                        byte[] chunkedParamBytes = ascii.GetBytes(chunkedParameters);
                        HttpClient requestToServer = new HttpClient();
                        requestToServer.Timeout = new TimeSpan(0, 0, timeOut);
                        MultipartFormDataContent form = new MultipartFormDataContent();
                        form.Add(data, "file", fileNameIn.Substring(pos, fileNameIn.Length - pos));
                        form.Add(new ByteArrayContent(strParamsBytes), "params");
                        form.Add(new ByteArrayContent(chunkedParamBytes), "chunkedParams");

                        try
                        {
                            HttpResponseMessage response = await requestToServer.PostAsync(url, form);

                            retVal = response.Content.ReadAsStringAsync().Result;
                            ulong fileLength = Convert.ToUInt64(fileStream.Length);
                            ulong processedBytes = (ulong)buffer.Length * (ulong)i;
                            ulong total = Convert.ToUInt64(fileLength - processedBytes);

                            if (i < totalChunks)
                            {
                                callback(fileLength, processedBytes, fileNameIn);
                            }

                            if ((fileLength - processedBytes) < Convert.ToUInt64(chunkSize))
                            {
                                buffer = new byte[fileLength - processedBytes];
                            }

                            requestToServer.Dispose();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("ERROR - There was an error sending the chunk request: " + e.Message);
                            retVal = "false";
                        }
                        i++;
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR - There was an error sending the chunk request: " + e.Message);
                retVal = "false";
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
        public string getFile(Dictionary<string, object> srcIdentifier, string fileNameOut, int timeOut, out int retCode)
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
            this.url = this.BASE_API_URL + "api2/file/read";

            if (!this.validateParams("read")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.sendDownloadRequest(fileNameOut, timeOut);
            if (this.dParams != null) { this.dParams.Clear(); }

            if (apiResult == "1")
            {   // Simulate a 200 OK if command succeeds
                retCode = 200;
                retVal.Add("code", "200");
                retVal.Add("message", "OK");
                retVal.Add("fileName", fileNameOut);
                apiResult = JsonSerializer.Serialize(retVal);
            }

            return apiResult;
        }

        // Uploads file to the user's Vault
        public Dictionary<string, object> putFile(string fileNameIn, Dictionary<string, object> srcIdentifier, int timeOut, out int retCode, out UInt64 fileId, out UInt64 fileAliasId)
        {
            string apiResult = "";
            retCode = 0;
            fileId = 0; fileAliasId = 0;
            Dictionary<string, object> retVal = null;
            //bool overwriteFile = false; UInt64 owFileId = 0;

            System.IO.FileInfo fInfo = new System.IO.FileInfo(fileNameIn);
            if (!fInfo.Exists)
            {
                throw new Exception("Incorrect Input File Path or File Does Not Exist");
            }

            //this.dParams = srcIdentifier;
            //if (!this.validateParams("write")) { throw new ArgumentException("Invalid Input Parameters"); }

            // No longer needed - automatic overwrites are handled by server with creating a new version of file
            //if (srcIdentifier.TryGetValue("overwriteFile", out object owFile))
            //{
            //    overwriteFile = (owFile.ToString() == "1" ? true : false);
            //    if (overwriteFile)
            //    {
            //        if (!srcIdentifier.TryGetValue("overwriteFileId", out object objOwFileId))
            //        {
            //            throw new ArgumentException("overwriteFileId parameter not specified");
            //        }
            //        owFileId = Convert.ToUInt64(objOwFileId);
            //        if (owFileId < 1) { throw new Exception("Invalid overwriteFileId value"); }
            //    }
            //}

            // Check if file exists on the server before uploading
            //Dictionary<string, object> fileInfoIdentifier = new Dictionary<string, object>();
            //if (overwriteFile)
            //{
            //    fileInfoIdentifier.Add("fileId", owFileId);
            //}
            //else
            //{
            //    fileInfoIdentifier.Add("fileName", fInfo.Name);
            //    if (srcIdentifier.TryGetValue("destFolderNames", out object tFolderNames))
            //    {
            //        fileInfoIdentifier.Add("folderNames", tFolderNames);
            //    }

            //    if (srcIdentifier.TryGetValue("destFolderId", out object tFolderId))
            //    {
            //        fileInfoIdentifier.Add("folderId", tFolderId);
            //    }
            //}

            //Dictionary<string, object> apiFileInfoResult = this.getFileInfo(fileInfoIdentifier, out retCode, out string fileName, out ulong fileSize, out ulong fileTimestamp, out ulong overwriteFileAliasId);
            //if (overwriteFile && retCode == 404)
            //{
            //    throw new Exception("Unable to Upload File, Overwrite Requested, but File Does Not Exist");
            //}
            //else if (!overwriteFile && retCode != 404)
            //{
            //    // File exists, or error occurred
            //    throw new Exception("Unable to Upload File, File with Same Name Already Exists in Destination Folder");
            //}

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/write";
            if (!this.validateParams("write")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendFileRequest(fileNameIn, timeOut);
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
            else
            {
                GetError(retVal, out retCode, out string msg, out string extMsg);
                if (this.verbosity)
                {
                    Console.WriteLine("- Error Occurred putFile, Code: " + retCode.ToString() + " Message: " + (msg != null ? msg.ToString() : "Not Available") + " Extended Message: " + (extMsg != null ? extMsg.ToString() : "Not Available"));
                }
            }

            return retVal;
        }

        // Uploads a file to the Vault Support system
        // This is used to transmit log/troubleshooting data from clients to a central repository on the server
        public Dictionary<string, object> putFileSupport(string fileNameIn, int timeOut, out int retCode, out string msg, out string extMsg)
        {
            string apiResult = ""; msg = ""; extMsg = ""; retCode = 0;
            Dictionary<string, object> retVal = null;

            System.IO.FileInfo fInfo = new System.IO.FileInfo(fileNameIn);
            if (!fInfo.Exists)
            {
                throw new Exception("Incorrect Input File Path or File Does Not Exist");
            }

            this.url = this.BASE_API_URL + "api2/support/writesupport";

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
        public Dictionary<string, object> putFileChunked(string fileNameIn, Dictionary<string, object> srcIdentifier, int chunkSize, int timeOut, Action<ulong, ulong, string> callback, System.Threading.CancellationTokenSource ct, out int retCode, out UInt64 fileId, out UInt64 fileAliasId)
        {
            string apiResult = "";
            retCode = 0;
            fileId = 0; fileAliasId = 0;
            Dictionary<string, object> retVal = null;
            //bool overwriteFile = false; UInt64 owFileId = 0;
            
            System.IO.FileInfo fInfo = new System.IO.FileInfo(fileNameIn);
            if (!fInfo.Exists)
            {
                throw new Exception("Incorrect Input File Path or File Does Not Exist");
            }

            //this.dParams = srcIdentifier;
            //if (!this.validateParams("write")) { throw new ArgumentException("Invalid Input Parameters"); }

            //if (srcIdentifier.TryGetValue("overwriteFile", out object owFile))
            //{
            //    overwriteFile = (owFile.ToString() == "1" ? true : false);
            //    if (overwriteFile)
            //    {
            //        if (!srcIdentifier.TryGetValue("overwriteFileId", out object objOwFileId))
            //        {
            //            throw new ArgumentException("overwriteFileId parameter not specified");
            //        }
            //        owFileId = Convert.ToUInt64(objOwFileId);
            //        if (owFileId < 1) { throw new Exception("Invalid overwriteFileId value"); }
            //    }
            //}

            //// Check if file exists on the server before uploading
            //Dictionary<string, object> fileInfoIdentifier = new Dictionary<string, object>();
            //if (overwriteFile)
            //{
            //    fileInfoIdentifier.Add("fileId", owFileId);
            //}
            //else
            //{
            //    fileInfoIdentifier.Add("fileName", fInfo.Name);
            //    if (srcIdentifier.TryGetValue("destFolderNames", out object tFolderNames))
            //    {
            //        fileInfoIdentifier.Add("folderNames", tFolderNames);
            //    }

            //    if (srcIdentifier.TryGetValue("destFolderId", out object tFolderId))
            //    {
            //        fileInfoIdentifier.Add("folderId", tFolderId);
            //    }
            //}

            //Dictionary<string, object> apiFileInfoResult = this.getFileInfo(fileInfoIdentifier, out retCode, out string fileName, out ulong fileSize, out ulong fileTimestamp, out ulong overwriteFileAliasId);
            //if (overwriteFile && retCode == 404)
            //{
            //    throw new Exception("Unable to Upload File, Overwrite Requested, but File Does Not Exist");
            //}
            //else if (!overwriteFile && retCode != 404)
            //{
            //    // File exists, or error occurred
            //    throw new Exception("Unable to Upload File, File with Same Name Already Exists in Destination Folder");
            //}

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/writechunked";
            if (!this.validateParams("write")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.SendFileRequestChunked(fileNameIn, chunkSize, timeOut, callback, ct).Result;
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
        public string readVersion(Dictionary<string, object> srcIdentifier, string fileNameOut, int timeOut, out int retCode)
        {
            string apiResult = "";
            retCode = 0;

            // Check fileNameOut contains a valid path
            System.IO.FileInfo fInfo = new System.IO.FileInfo(fileNameOut);
            if (!fInfo.Directory.Exists)
            {
                throw new Exception("Incorrect Output File Path or Path Does Not Exist");
            }

            this.dParams = srcIdentifier;
            this.url = this.BASE_API_URL + "api2/file/readversion";

            if (!this.validateParams("readversion")) { throw new ArgumentException("Invalid Input Parameters"); }

            apiResult = this.sendDownloadRequest(fileNameOut, timeOut);
            if (this.dParams != null) { this.dParams.Clear(); }

            if (apiResult == "1")
            {   // Simulate a 200 OK if command succeeds
                retCode = 200;
                Dictionary<string, object> retVal = new Dictionary<string, object>();
                retVal.Add("code", 200);
                retVal.Add("message", "OK");
                retVal.Add("fileName", fileNameOut);

                apiResult = JsonSerializer.Serialize(retVal);
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

            apiResult = this.sendDownloadRequest(fileNameOut, timeOut);
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
         * Converts a destination dictionary to a source dictionary
         * Useful for calling getFileInfo() before a write/writechunked operation to check if the destination exists
         * if allKeys = true, will convert all keys, otherwise will just convert/copy destFileName, destFolderNames, destFolderId, and destFilePath
         */
        public Dictionary<string, object> convertDestinationToSourceDictionary(Dictionary<string, object> destDictIn, bool allKeys)
        {
            // Copy all keys in the dictionary, but rename "destFileName", "destFolderNames", "destFolderId", "destFilePath"
            Dictionary<string, object> result = new Dictionary<string, object>();

            foreach (KeyValuePair<string, object> keyValue in destDictIn)
            {
                if (keyValue.Key == "destFileName")
                {
                    result.Add("fileName", keyValue.Value.ToString());
                }
                else if (keyValue.Key == "destFolderNames")
                {
                    result.Add("folderNames", keyValue.Value);
                    // To Do - unknow deep or shallow copy of a string array
                }
                else if (keyValue.Key == "destFolderId")
                {
                    result.Add("folderId", keyValue.Value.ToString());
                }
                else if (keyValue.Key == "destFilePath")
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
