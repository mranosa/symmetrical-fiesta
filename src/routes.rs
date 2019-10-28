use crate::ipfilter;

use actix_web::{web, Error, HttpResponse};
use futures::future::{ok, Future};
use std::sync::Mutex;
use ipfilter::IpFilter;

pub fn whitelist_page(data: web::Data<Mutex<IpFilter>>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    // SOURCE:  https://stackoverflow.com/questions/48102662/use-all-but-the-last-element-from-an-iterator
    let mut whitelist_str = String::new();
    let ips = data.lock().unwrap().whitelist.clone();
    let mut chunks = ips.chunks(2).peekable();
    let mut is_last = false;

    while let Some(chunk) = chunks.next() {
        if !chunks.peek().is_some() {
            is_last = true;
        }

        for ip in chunk.iter() {
            whitelist_str.push_str(&ip.to_string());
            if !is_last {
                whitelist_str.push_str(", ");
            }
        }
    }

    Box::new(ok::<_, Error>(
        HttpResponse::Ok().content_type("text/html").body(whitelist_str),
    ))
}

pub fn secret_page(data: web::Data<Mutex<IpFilter>>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let secret_number = data.lock().unwrap().secret_number.to_string();;

    println!("secret_number: {:?}", secret_number);

    Box::new(ok::<_, Error>(
        HttpResponse::Ok().content_type("text/html").body(secret_number),
    ))
}