//! Simple echo websocket server.
//! Open `http://localhost:8080/ws/index.html` in browser
//! or [python console client](https://github.com/actix/examples/blob/master/websocket/websocket-client.py)
//! could be used for testing.
extern crate rand;

mod routes;
mod ipfilter;

use rand::Rng;

use std::time::{Duration, Instant};

use actix::prelude::*;
use actix_web::{middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use actix_web_actors::ws;
use ipfilter::IpFilter;

use std::sync::Mutex;

/// How often heartbeat pings are sent
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// How long before lack of client response causes a timeout
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

fn generate_random_number() -> u32 {
    let mut rng = rand::thread_rng();
    let random_number: u32 = rng.gen();
    
    random_number
}

/// do websocket handshake and start `MyWebSocket` actor
fn ws_index(data: web::Data<Mutex<IpFilter>>, r: HttpRequest, stream: web::Payload) -> Result<HttpResponse, Error> {
    // SOURCE: https://stackoverflow.com/questions/52919494/is-there-simpler-method-to-get-the-string-value-of-an-actix-web-http-header
    fn get_secret_number<'a>(req: &'a HttpRequest) -> Option<&'a str> {
        req.headers().get("secret-number")?.to_str().ok()
    }

    // get client details
    let connection_info = r.connection_info();
    let remote_address_str = connection_info.remote().unwrap().to_string();
    let remote_address:Vec<&str>= remote_address_str.split(":").collect();
    let ip_address = remote_address[0].to_string();
    let mut secret_number = "none".to_string();
    if let Some(num_from_req) = get_secret_number(&r) {
        secret_number = num_from_req.to_string();
    }

    // validate client details against ip filter
    let mut ip_filter = data.lock().unwrap();
    let exist_in_whitelist = ip_filter.exists_in_whitelist(&ip_address) ;
    let secret_number_valid = ip_filter.is_secret_number_valid(&secret_number);
    let add_to_whitelist = !exist_in_whitelist && secret_number_valid;
    let mut is_authorized = exist_in_whitelist;

    println!("-------------> exist_in_whitelist {:?}", exist_in_whitelist);
    println!("-------------> secret_number_valid {:?}", secret_number_valid);
    println!("-------------> add_to_whitelist {:?}", add_to_whitelist);

    if add_to_whitelist {
        ip_filter.add_ip(ip_address);

        // randomly generate new secret number
        if generate_random_number() % 3 == 0 {
            ip_filter.new_secret_number(generate_random_number());
        }

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
    
    let ip_filter = IpFilter{
        whitelist: vec![
            "192.192.192.1".to_string(),
            "192.192.192.2".to_string(),
            "192.192.192.3".to_string()
        ],
        secret_number: generate_random_number(),
        secret_number_used: false
    };

    let ip_filter_data = web::Data::new(Mutex::new(ip_filter));
    
    HttpServer::new(move || {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .register_data(ip_filter_data.clone())
            // websocket route
            .service(web::resource("/ws/").route(web::get().to(ws_index)))
            // web pages
            .route("/whitelist", web::to_async(routes::whitelist_page))
            .route("/secret", web::to_async(routes::secret_page))
    })
    // start http server on 127.0.0.1:8080
    .bind("127.0.0.1:8080")?
    .run()
}