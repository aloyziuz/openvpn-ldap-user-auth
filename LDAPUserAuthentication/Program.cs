using LdapHelper;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace LDAPUserAuthentication
{
    class Program
    {
        private static readonly string confFile = 
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
                "LDAPAuthentication\\LDAPUserAuthentication.conf");
        private static readonly string logFile = 
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
                "LDAPAuthentication\\LDAPAuthenticationLog.log");

        static int Main(string[] args)
        {
            if(args.Count() > 0)
            {
                string userpasspath = args[0];
                var s = File.ReadAllText(userpasspath).Split('\n');
                if (s.Count() > 1)
                {
                    string username = s[0].Trim();
                    string pass = s[1].Trim();
                    string server = "";
                    string group = "";
                    string dir = "";
                    string[] conf = null;

                    //read configuration file
                    try
                    {
                        conf = File.ReadAllText(confFile).Split('\n');
                    }
                    catch(FileNotFoundException e)
                    {
                        File.AppendAllText(logFile, string.Format("{0}: Configuration file not found.\n", DateTime.Now));
                        return 1;
                    }

                    foreach (string line in conf)
                    {
                        if (line.StartsWith("Server ="))
                        {
                            server = line.Replace("Server =", "").Trim();
                        }
                        else if (line.StartsWith("DN ="))
                        {
                            dir = line.Replace("DN =", "").Trim();
                        }
                        else if (line.StartsWith("Group ="))
                        {
                            group = line.Replace("Group =", "").Trim();
                        }
                    }
                    //test user is valid
                    //bool isvaliduser = ValidateUser(server, username, pass, dir, group);
                    LDAPHelper h = new LDAPHelper(server);
                    bool isvaliduser = false;
                    try
                    {
                        isvaliduser = h.IsAuthenticated(dir, username, pass);
                    }
                    catch(Exception e)
                    {
                        File.AppendAllText(logFile, e.Message);
                        return 0;
                    }
                    //raise exception if user is not valid
                    if (!isvaliduser)
                        return 1;
                    else
                    {
                        File.AppendAllText(logFile, string.Format("{0}: User {1} authenticated.\n",
                            DateTime.Now, username));
                        return 0;
                    }
                }
                else
                {
                    File.AppendAllText(logFile, string.Format("{0}: Username and password file consist of < 2 lines ({1}).\n",
                        DateTime.Now, userpasspath));
                    return 1;
                }
            }
            else
            {
                File.AppendAllText(logFile, string.Format("{0}: Username and password file is not given.\n", DateTime.Now));
                return 1;
            }
        }

        private static bool IsMemberOfGroup(string server, string username, string pass, string groupname, string domain)
        {
            // set up domain context
            PrincipalContext ctx = new PrincipalContext(ContextType.ApplicationDirectory, server, domain, 
                ContextOptions.SimpleBind, "cn="+username, pass);

            // find a user
            UserPrincipal user = UserPrincipal.FindByIdentity(ctx, username);

            if (user != null)
            {
                var groups = user.GetGroups();
                // or there's also:
                //var authGroups = userByEmail.GetAuthorizationGroups()
            }
            return false;
        }

        private static bool ValidateUser(string server, string username, string pass, string domain, string groupname)
        {
            bool res = false;
            string fulluname = string.Format("cn={0},{1}", username, domain);
            var cred = new NetworkCredential(fulluname, pass);
            var serverid = new LdapDirectoryIdentifier(server);
            using (var con = new LdapConnection(serverid, cred, AuthType.Basic))
            {
                try
                {
                    con.Bind();
                    res = true;
                }
                catch (Exception e)
                {
                    res = false;
                    File.AppendAllText(logFile, string.Format("{0}: Unable to authenticate user {1} to server {2}. Message: {3}\n", 
                        DateTime.Now, fulluname, server, e.Message));
                }
                return res;
            }
        }
    }
}
