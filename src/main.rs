//! Simple echo websocket server.
//! Open `http://localhost:8080/ws/index.html` in browser
//! or [python console client](https://github.com/actix/examples/blob/master/websocket/websocket-client.py)
//! could be used for testing.
#[macro_use(lazy_static)]
extern crate lazy_static;
extern crate rand;

use rand::Rng;

use std::time::{Duration, Instant};

use actix::prelude::*;
use actix_files as fs;
use actix_web::{error, middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use actix_web_actors::ws;
use futures::future::{ok, err, Future};

use std::sync::Mutex;

/// How often heartbeat pings are sent
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// How long before lack of client response causes a timeout
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

// SOURCE: https://stackoverflow.com/questions/27791532/how-do-i-create-a-global-mutable-singleton
// SOURCE: https://stackoverflow.com/questions/29654927/how-do-i-assign-a-string-to-a-mutable-static-variable
// TODO: Refactor to non-global variable implementation
// println!("WHITELIST: {:?}", WHITELIST.lock().unwrap());
lazy_static! {
    static ref WHITELIST: Mutex<Vec<String>> = Mutex::new(vec![]);
    static ref SECRET_NUMBER: Mutex<u32> = Mutex::new(generate_random_number());
    static ref SECRET_NUMBER_USED: Mutex<bool> = Mutex::new(false);
}

fn generate_random_number() -> u32 {
    let mut rng = rand::thread_rng();
    let random_number: u32 = rng.gen();
    
    random_number
}

fn generate_secret_number() {
    // SOURCE: https://www.reddit.com/r/rust/comments/9wd8s7/how_to_unlock_a_mutex/
    let mut secret_number = SECRET_NUMBER.lock().unwrap();
    *secret_number = generate_random_number();
    std::mem::drop(secret_number);

    let mut secret_number_used = SECRET_NUMBER_USED.lock().unwrap();
    *secret_number_used = false;
    std::mem::drop(secret_number_used);

    println!("NEW SECRET NUMBER: {:?}", SECRET_NUMBER.lock().unwrap());
}

// TODO: How and where to invoke this? on the web page?
// add_ip("192.168.1.2".to_string());
fn add_ip(ip: String) {
    println!("WHITELIST BEFORE: {:?}", WHITELIST.lock().unwrap());
    WHITELIST.lock().unwrap().push(ip);


    println!("WHITELIST AFTER: {:?}", WHITELIST.lock().unwrap());

    // randomly generate new secret number
    if generate_random_number() % 3 == 0 {
        generate_secret_number();
    }
}

fn remove_ip(ip: String) {
    let index = WHITELIST.lock().unwrap().iter().position(|x| *x == ip).unwrap();
    WHITELIST.lock().unwrap().remove(index);
}

fn whitelist() -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    // SOURCE:  https://stackoverflow.com/questions/48102662/use-all-but-the-last-element-from-an-iterator
    let mut whitelist_str = String::new();
    let ips = WHITELIST.lock().unwrap();
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

    println!("WHITELIST: {:?}", whitelist_str);

    Box::new(ok::<_, Error>(
        HttpResponse::Ok().content_type("text/html").body(whitelist_str),
    ))
}

fn secret() -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let secret_number = SECRET_NUMBER.lock().unwrap().to_string();;

    println!("secret_number: {:?}", secret_number);

    Box::new(ok::<_, Error>(
        HttpResponse::Ok().content_type("text/html").body(secret_number),
    ))
}

fn exists_in_whitelist(ip: &String) -> bool {
    let whitelist = WHITELIST.lock().unwrap();
    
    if !whitelist.contains(&ip) {
        return false;
    }

    return true;
}

fn secret_number_valid(secret_number: &String) -> bool {
    let mut is_used_guard = SECRET_NUMBER_USED.lock().unwrap();
    let is_used = *is_used_guard;
    std::mem::drop(is_used_guard);

    if SECRET_NUMBER.lock().unwrap().to_string() == secret_number.to_string() && is_used == false {
        return true;
    }

    return false;
}

// SOURCE: https://stackoverflow.com/questions/52919494/is-there-simpler-method-to-get-the-string-value-of-an-actix-web-http-header
fn get_secret_number<'a>(req: &'a HttpRequest) -> Option<&'a str> {
    req.headers().get("secret-number")?.to_str().ok()
}

/// do websocket handshake and start `MyWebSocket` actor
fn ws_index(r: HttpRequest, stream: web::Payload) -> Result<HttpResponse, Error> {
    let mut secret_number = "none".to_string();
    if let Some(num_from_req) = get_secret_number(&r) {
        secret_number = num_from_req.to_string();
    }
    let connection_info = r.connection_info();
    let remote_address_str = connection_info.remote().unwrap().to_string();
    let remote_address:Vec<&str>= remote_address_str.split(":").collect();
    let ip_address = remote_address[0].to_string();
    let exist_in_whitelist = exists_in_whitelist(&ip_address);
    let secret_number_valid = secret_number_valid(&secret_number);
    let add_to_whitelist = !exist_in_whitelist && secret_number_valid;
    let mut is_authorized = exist_in_whitelist;

    println!("-------------> exist_in_whitelist {:?}", exist_in_whitelist);
    println!("-------------> secret_number_valid {:?}", secret_number_valid);
    println!("-------------> add_to_whitelist {:?}", add_to_whitelist);

    if add_to_whitelist {
        add_ip(ip_address.to_string());

        let mut secret_number_used = SECRET_NUMBER_USED.lock().unwrap();
        *secret_number_used = true;
        std::mem::drop(secret_number_used);

        is_authorized = true;        
    }

    if is_authorized {
        let res = ws::start(MyWebSocket::new(), &r, stream);
        println!("{:?}", res.as_ref().unwrap());
        return res;
    } else {
        return Ok(HttpResponse::Unauthorized().finish());
    }
}

/// websocket connection is long running connection, it easier
/// to handle with an actor
struct MyWebSocket {
    /// Client must send ping at least once per 10 seconds (CLIENT_TIMEOUT),
    /// otherwise we drop connection.
    hb: Instant,
}

impl Actor for MyWebSocket {
    type Context = ws::WebsocketContext<Self>;

    /// Method is called on actor start. We start the heartbeat process here.
    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
    }
}

/// Handler for `ws::Message`
impl StreamHandler<ws::Message, ws::ProtocolError> for MyWebSocket {
    fn handle(&mut self, msg: ws::Message, ctx: &mut Self::Context) {
        // process websocket messages
        println!("WS: {:?}", msg);
        match msg {
            ws::Message::Ping(msg) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            ws::Message::Pong(_) => {
                self.hb = Instant::now();
            }
            ws::Message::Text(text) => ctx.text(text),
            ws::Message::Binary(bin) => ctx.binary(bin),
            ws::Message::Close(_) => {
                ctx.stop();
            }
            ws::Message::Nop => (),
        }
    }
}

impl MyWebSocket {
    fn new() -> Self {
        Self { hb: Instant::now() }
    }

    /// helper method that sends ping to client every second.
    ///
    /// also this method checks heartbeats from client
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // check client heartbeats
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                // heartbeat timed out
                println!("Websocket Client heartbeat failed, disconnecting!");

                // stop actor
                ctx.stop();

                // don't try to send a ping
                return;
            }

            ctx.ping("");
        });
    }
}

fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_server=info,actix_web=info");
    env_logger::init();
    
    // prepare whitelist
    // add_ip("127.0.0.1".to_string());
    add_ip("127.0.0.2".to_string());
    add_ip("127.0.0.3".to_string());
    
    HttpServer::new(|| {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            // websocket route
            .service(web::resource("/ws/").route(web::get().to(ws_index)))
            // web pages
            .route("/whitelist", web::to_async(whitelist))
            .route("/secret", web::to_async(secret))
    })
    // start http server on 127.0.0.1:8080
    .bind("127.0.0.1:8080")?
    .run()
}