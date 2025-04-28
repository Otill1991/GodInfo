using System;

namespace GodInfo.Helper.Models
{
    // Adapted from SharpWeb and Pillager
    public class FirefoxLogin
    {
        public int id { get; set; }
        public string hostname { get; set; }
        public string httpRealm { get; set; }
        public string formSubmitURL { get; set; }
        public string usernameField { get; set; }
        public string passwordField { get; set; }
        public string encryptedUsername { get; set; }
        public string encryptedPassword { get; set; }
        public string guid { get; set; }
        public int encType { get; set; }
        public long timeCreated { get; set; }
        public long timeLastUsed { get; set; }
        public long timePasswordChanged { get; set; }
        public int timesUsed { get; set; }
        public string syncCounter { get; set; }
        public string everSynced { get; set; }
        public string encryptedUnknownFields { get; set; }
    }
} 