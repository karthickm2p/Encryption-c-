        #region Encrypt Request
        public string encodeRequest(string requestData, string messageRefNo, string entity)
        {
            string encodedRequest = null;

            YappayEncryptedRequest request = new YappayEncryptedRequest();
            byte[] sessionKeyByte = this.generateToken();
            request.token = this.generateDigitalSignedToken(requestData);
            request.body = this.encryptData(requestData, sessionKeyByte, messageRefNo);
            request.key = this.encryptKey(sessionKeyByte);
            request.entity = this.encryptKey(Encoding.ASCII.GetBytes(entity));
            request.refNo = messageRefNo;

            DataContractJsonSerializer js = new DataContractJsonSerializer(typeof(YappayEncryptedRequest));
            MemoryStream ms = new MemoryStream();
            js.WriteObject(ms, request);

            ms.Position = 0;
            StreamReader sr = new StreamReader(ms);
            encodedRequest = sr.ReadToEnd();
            sr.Close();
            ms.Close(); 
            return encodedRequest;
        }

        public string generateDigitalSignedToken(string requestData)
        {
            string signedToken = null;
            try
            {
                byte[] requestDataBytes = Encoding.ASCII.GetBytes(requestData);

                RSACryptoServiceProvider rsa = readPrivateKeyFromFile(ConfigurationManager.AppSettings.Get("PrivateKey"));
                SHA1Managed sha = new SHA1Managed();
                byte[] signedTokenBytes = rsa.SignData(requestDataBytes, sha);

                signedToken = base64urlencode(signedTokenBytes);
            }
            catch
            {
                throw;
            }
            return signedToken;
        }
        public byte[] generateToken()
        {
            byte[] symmetricKey = null;
            try
            {
                AesManaged objAesKey = new AesManaged();
                objAesKey.KeySize = 128;
                objAesKey.Mode = CipherMode.CBC;
                objAesKey.Padding = PaddingMode.PKCS7;

                objAesKey.GenerateKey();
                symmetricKey = objAesKey.Key;
            }
            catch
            {
                throw;
            }

            return symmetricKey;
        }
        public string encryptData(string requestData, byte[] sessionKey,
                                  string messageRefNo)
        {
            string encryptedText = null;
            try
            {
                AesManaged objAesKey = new AesManaged();
                objAesKey.KeySize = 128;
                objAesKey.Mode = CipherMode.CBC;
                objAesKey.Padding = PaddingMode.PKCS7;

                objAesKey.Key = sessionKey;
                objAesKey.IV = Encoding.ASCII.GetBytes(messageRefNo);
                
                byte[] requestDataBytes = Encoding.ASCII.GetBytes(requestData);
                
                MemoryStream ms = new MemoryStream();
                CryptoStream cs = new CryptoStream(ms, objAesKey.CreateEncryptor(), CryptoStreamMode.Write);
                cs.Write(requestDataBytes, 0, requestDataBytes.Length);
                if (cs != null)
                {
                    cs.Close();
                }
                byte[] encryptedTextBytes = ms.ToArray();

                encryptedText = base64urlencode(encryptedTextBytes);

            }
            catch
            {
                throw;
            }
            return encryptedText;
        }
        public string encryptKey(byte[] sessionKey)
        {
            string encryptedKey = null;
            try
            {
                RSACryptoServiceProvider rsa = readPublicKeyFromFile(ConfigurationManager.AppSettings.Get("PublicKey"));

                byte[] encryptedKeyBytes = rsa.Encrypt(sessionKey, false);
                encryptedKey = base64urlencode(encryptedKeyBytes);
            }
            catch
            {
                throw;
            }

            return encryptedKey;
        }
        #endregion
