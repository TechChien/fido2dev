using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using MySql.Data.MySqlClient;
 
namespace fido2prj.Fido2Lib
{
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

        public void recordCredentialDB()
        {
            using (MySqlConnection connection = new MySqlConnection(connectionString))
            {
                connection.Open();
                string sql = "insert into userCredential(id, chanllege, username) values(@id, @chanllege, @username)";
                using (MySqlCommand mySqlCommand = new MySqlCommand(sql, connection))
                {
                    // to do 
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
                    //sql = string.Format("delete from tbl_temp  where userHandle = {0}", userHandle);
                    //using (MySqlCommand mySqlCommand = new MySqlCommand(sql, connection))
                    //{
                    //    // to do 
                    //    mySqlCommand.ExecuteNonQuery();
                    //}
                }
                return respStr;
            }
            catch(Exception e)
            {
                return "";
            }
            
        }


        // get credential from db
        public void getCredentialDB(string username)
        {

        }

        // update sigCount
        public void updateSigCountDB()
        {

        }

    }
}