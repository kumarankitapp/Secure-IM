class register_users:


    def creds(self,username):

        self.credentials={
            "ankit":"password",
            "rucha":"rucha",
            "admin":"12345",
            "test":"9999",
            "root":"toor",
            "administrator":"0000"
        }

        if username in self.credentials:
            return 1

        else:
            return 0




