pub struct IpFilter {
    pub whitelist: Vec<String>,
    pub secret_number: u32,
    pub secret_number_used: bool
}

impl IpFilter {
    pub fn new_secret_number(&mut self, number: u32) {
        self.secret_number = number;
        self.secret_number_used = false;
    }

    pub fn add_ip(&mut self, ip: String) {
        println!("WHITELIST BEFORE: {:?}", self.whitelist);
        self.whitelist.push(ip);
        println!("WHITELIST AFTER: {:?}", self.whitelist);
    }

    #[allow(dead_code)]
    pub fn remove_ip(&mut self, ip: String) {
        let index = self.whitelist.iter().position(|x| *x == ip);
        self.whitelist.remove(index.unwrap());
    }

    pub fn exists_in_whitelist(&self, ip: &String) -> bool {
        return self.whitelist.contains(&ip);
    }

    pub fn is_secret_number_valid (&self, number: &String) -> bool {
        return self.secret_number.to_string() == *number && !self.secret_number_used;
    }
}