using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using MySql.Data.MySqlClient;
 
namespace fido2prj
{

    public class AssertionOption
    {
        public AssertionOption(string cred, string type, string userHanle) { this.CredentialId = cred; this.CredType = type; this.UserHandle = userHanle; }
        public string CredentialId { get; set; }
        public string CredType { get; set; }

        public string UserHandle { get; set; }
    }


    public class DBOperator
    {
        

        public DBOperator() { }

        const string database = "fido2";
        const string databaseServer = "localhost";
        const string databaseUser = "cvesa";
        const string databasePassword = "123456";

        string connectionString = $"server={databaseServer};" + $"user={databaseUser};" + $"password={databasePassword};" + $"database={database};charset=utf8;";

        public void recordChanllegeDB(byte[] id, byte[] chanllege)
        {
            using (MySqlConnection connection = new MySqlConnection(connectionString))
            {
                connection.Open();
                string sql = "insert into tbl_temp(userHandle, challenge) values(@userHandle, @challenge)";
                using(MySqlCommand mySqlCommand = new MySqlCommand(sql, connection))
                {
                    mySqlCommand.Parameters.AddWithValue("@userHandle", Base64UrlHelper.EncodeBase64Url(id));
                    mySqlCommand.Parameters.AddWithValue("@challenge", Base64UrlHelper.EncodeBase64Url(chanllege));
                    mySqlCommand.ExecuteNonQuery();
                }
            }
        }

        public void recordCredentialDB(string username, string credentialId, byte[] publicKey,string userHandle, uint SigCount, byte[] aaguid)
        {
            using (MySqlConnection connection = new MySqlConnection(connectionString))
            {
                connection.Open();
                string sql = "insert into tbl_userCredential(userId, credentialId , publicKey, userHandle, SignatureCounter,AaGuid ) values(@userId, @credentialId , @publicKey, @userHandle, @SignatureCounter,@AaGuid)";
                using (MySqlCommand mySqlCommand = new MySqlCommand(sql, connection))
                {
                    // to do 
                    mySqlCommand.Parameters.AddWithValue("@userId", username);
                    mySqlCommand.Parameters.AddWithValue("@credentialId", credentialId);
                    mySqlCommand.Parameters.AddWithValue("@publicKey", Base64UrlHelper.EncodeBase64Url(publicKey));
                    mySqlCommand.Parameters.AddWithValue("@userHandle", userHandle);
                    mySqlCommand.Parameters.AddWithValue("@SignatureCounter", SigCount);
                    mySqlCommand.Parameters.AddWithValue("@AaGuid", Base64UrlHelper.EncodeBase64Url(aaguid));
                    mySqlCommand.ExecuteNonQuery();
                }
            }
        }

        // get credential from db
        public AssertionOption getCredentialDB(string username)
        {
            AssertionOption AssertionOption = null;
            try
            {
                using (MySqlConnection connection = new MySqlConnection(connectionString))
                {
                    connection.Open();
                    string sql = "select credentialId,CredType,userHandle from tbl_usercredential where userId = @userId";
                    using (MySqlCommand mySqlCommand = new MySqlCommand(sql, connection))
                    {
                        mySqlCommand.Parameters.AddWithValue("@userId", username);
                        // to do 
                        using (MySqlDataReader dr = mySqlCommand.ExecuteReader())
                        {
                            while (dr.Read())
                            {
                                AssertionOption = new AssertionOption(dr["credentialId"].ToString(), dr["CredType"].ToString(), dr["userHandle"].ToString());
                            }
                        }
                    }
                }
                return AssertionOption;
            }
            catch (Exception e)
            {
                return null;
            }
        }

        // update sigCount
        public void updateSigCountDB(uint sigCount, string userid , string credentialId, byte[] aaguid )
        {
            using (MySqlConnection connection = new MySqlConnection(connectionString))
            {
                connection.Open();
                string sql = "update tbl_usercredential set SignatureCounter = @sigCount where userId = @userId and credentialId = @credentialId and AaGuid = @AaGuid";
                using (MySqlCommand mySqlCommand = new MySqlCommand(sql, connection))
                {
                    // to do 
                    mySqlCommand.Parameters.AddWithValue("@sigCount", sigCount);
                    mySqlCommand.Parameters.AddWithValue("@userId", userid);
                    mySqlCommand.Parameters.AddWithValue("@credentialId", credentialId);
                    mySqlCommand.Parameters.AddWithValue("@AaGuid", Base64UrlHelper.EncodeBase64Url(aaguid));
                    mySqlCommand.ExecuteNonQuery();
                }
            }
        }

        public string getChallengeFromTemp(string userHandle)
        {
            try
            {
                string respStr = "";
                using (MySqlConnection connection = new MySqlConnection(connectionString))
                {
                    connection.Open();
                    string sql = "select challenge from tbl_temp where userHandle = @userHandle";
                    using (MySqlCommand mySqlCommand = new MySqlCommand(sql, connection))
                    {
                        mySqlCommand.Parameters.AddWithValue("@userHandle", userHandle);
                        // to do 
                        using (MySqlDataReader dr = mySqlCommand.ExecuteReader())
                        {
                            while (dr.Read())
                            {
                                respStr = dr["challenge"].ToString();
                            }
                        }
                    }
                    sql = "delete from tbl_temp where userHandle = @userHandle";
                    using (MySqlCommand mySqlCommand = new MySqlCommand(sql, connection))
                    {
                        mySqlCommand.Parameters.AddWithValue("@userHandle", userHandle);
                        // to do 
                        mySqlCommand.ExecuteNonQuery();
                    }
                }
                return respStr;
            }
            catch (Exception e)
            {
                return "";
            }

        }

        public string getPublickKey(string userid)
        {
            try
            {
                string respStr = "";
                using (MySqlConnection connection = new MySqlConnection(connectionString))
                {
                    connection.Open();
                    string sql = "select publicKey from tbl_usercredential where userId = @userid";
                    using (MySqlCommand mySqlCommand = new MySqlCommand(sql, connection))
                    {
                        mySqlCommand.Parameters.AddWithValue("@userid", userid);
                        // to do 
                        using (MySqlDataReader dr = mySqlCommand.ExecuteReader())
                        {
                            while (dr.Read())
                            {
                                respStr = dr["publicKey"].ToString();
                            }
                        }
                    }
                    
                }
                return respStr;
            }
            catch (Exception e)
            {
                return "";
            }
        }
    }
}