class LinuxIAMConfig{
    //U-01
    public Boolean PermitRemoteRootLogin;
    //U-01
    public int PasswordHistory;
    public int PasswordLength;
    public int PasswordMinDigit;
    public int PasswordMinUppercase;
    public int PasswordMinLowercase;
    public int PasswordMinSpecial;
    public int PasswordMaxDays;
    public int PasswordMinDays;
    //U-01
    public Boolean AccountFaillock;
    public int AccountFaillockRetries;

    //U-01
    public Boolean isPasswordEncrypted;

    //U-01
    public List<string> UsersWithUID0;
    //U-01
    public List<string> SuFileGroup;

    public List<string> allUsers;
    public List<string> AdminGroupUsers;

    public List<string> GroupWithNoUser;

    public List<string> DuplicateUser;

    public List<string> UsersWithShell;

    public int SessionTimeout;

    public string PasswordEncryptionAlgorithm;


}