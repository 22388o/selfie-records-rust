use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use regex::Regex;
use log::{info, debug, error, LevelFilter};
use simple_logger::SimpleLogger;
use trust_dns_resolver::{Resolver, config::*};

const DEFAULT_RECORDS: [&str; 4] = ["bitcoin-payment", "pgp", "nostr", "node-uri"];

#[derive(Debug)]
struct SelfieRecordsSDK {
    resolver: Resolver,
}

impl SelfieRecordsSDK {
    fn new(debug: bool) -> Self {
        if debug {
            SimpleLogger::new().with_level(LevelFilter::Debug).init().unwrap();
        } else {
            SimpleLogger::new().with_level(LevelFilter::Error).init().unwrap();
        }

        let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
        SelfieRecordsSDK { resolver }
    }

    fn get_records(&self, name: &str, filters: Option<Vec<&str>>, dns_server: Option<&str>) -> HashMap<String, HashMap<String, Option<String>>> {
        let filters = filters.unwrap_or(DEFAULT_RECORDS.to_vec());
        let dns_server = dns_server.unwrap_or("8.8.8.8");

        let mut results = HashMap::new();

        // Update DNS server if provided
        if let Ok(ip) = Ipv4Addr::from_str(dns_server) {
            self.resolver.update_nameservers(&ResolverConfig::from_parts(None, vec![NameServerConfig {
                socket_addr: (ip, 53).into(),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_anchor: None,
                tls_config: None,
            }])).unwrap();
        }

        for key in filters.iter() {
            let domain_check = self.validate_domain_or_subdomain(key, name);
            let email_check = self.validate_email_address(key, name);

            if domain_check.is_some() && email_check.is_some() {
                let mut error_map = HashMap::new();
                error_map.insert("value".to_string(), None);
                error_map.insert("error".to_string(), Some(domain_check.unwrap_or(email_check.unwrap())));
                results.insert(key.to_string(), error_map);
                continue;
            }

            let domain_name = self.get_txt_record_key(name, key);
            debug!("Resolving TXT record for: {}", domain_name);

            match self.resolve_txt(&domain_name) {
                Ok(answers) => {
                    if answers.is_empty() {
                        let mut error_map = HashMap::new();
                        error_map.insert("value".to_string(), None);
                        error_map.insert("error".to_string(), Some("No TXT records found".to_string()));
                        results.insert(key.to_string(), error_map);
                    } else {
                        let value = answers.join(" ");
                        let mut success_map = HashMap::new();
                        success_map.insert("value".to_string(), Some(value));
                        success_map.insert("error".to_string(), None);
                        results.insert(key.to_string(), success_map);
                    }
                }
                Err(e) => {
                    error!("Error processing {}: {}", key, e);
                    results.insert(key.to_string(), self.handle_error(key, &e));
                }
            }
        }

        results
    }

    fn resolve_txt(&self, name: &str) -> Result<Vec<String>, String> {
        match self.resolver.txt_lookup(name) {
            Ok(lookup) => Ok(lookup.iter().map(|txt| txt.to_string()).collect()),
            Err(e) => Err(format!("Error resolving TXT record for {}: {:?}", name, e)),
        }
    }

    fn get_txt_record_key(&self, name: &str, key: &str) -> String {
        if name.contains('@') {
            let parts: Vec<&str> = name.split('@').collect();
            format!("{}.user._{}.{}", parts[0], key, parts[1])
        } else {
            format!("_{}.{}", key, name)
        }
    }

    fn validate_email_address(&self, key: &str, name: &str) -> Option<String> {
        let email_regex = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
        if !email_regex.is_match(name) {
            Some(format!("Invalid email name for key: {}", key))
        } else {
            None
        }
    }

    fn validate_domain_or_subdomain(&self, key: &str, name: &str) -> Option<String> {
        let domain_regex = Regex::new(r"^(?!:\/\/)([a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)+.*)$").unwrap();
        if !domain_regex.is_match(name) {
            Some(format!("Invalid domain or subdomain name for key: {}", key))
        } else {
            None
        }
    }

    fn handle_error(&self, key: &str, error: &str) -> HashMap<String, Option<String>> {
        let mut error_map = HashMap::new();
        error_map.insert("value".to_string(), None);
        error_map.insert("error".to_string(), Some(error.to_string()));
        error_map
    }
}

fn main() {
    let sdk = SelfieRecordsSDK::new(true);
    let records = sdk.get_records("example.com", None, Some("8.8.8.8"));
    println!("{:?}", records);
}
