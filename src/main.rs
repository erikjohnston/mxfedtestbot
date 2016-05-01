#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

#[macro_use] extern crate clap;
extern crate hyper;
extern crate mxfedtest;
extern crate rustc_serialize;
extern crate serde;
extern crate serde_json;
extern crate toml;
extern crate chrono;

use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::str::FromStr;

use hyper::Client;
use hyper::header::ContentType as ContentTypeHeader;

use rustc_serialize::hex::ToHex;
use rustc_serialize::base64::FromBase64;

use chrono::naive::datetime::NaiveDateTime;


#[derive(Serialize, Deserialize, Debug)]
struct EventContent {
    body: Option<String>,
    msgtype: Option<String>,
    format: Option<String>,
    formatted_body: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Event {
    content: EventContent,
    #[serde(rename="type")]
    event_type: String,
    state_key: Option<String>,
    sender: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SyncRoomTimelineResponse {
    events: Vec<Event>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SyncRoomResponse {
    timeline: SyncRoomTimelineResponse,
}

#[derive(Serialize, Deserialize, Debug)]
struct SyncRoomsResponse {
    join: BTreeMap<String, SyncRoomResponse>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SyncResponse {
    next_batch: String,
    rooms: SyncRoomsResponse,
}

#[derive(Deserialize, Debug)]
struct Config {
    server_url: String,
    access_token: String,
}


fn main() {
    let matches = clap::App::new("matrix-bot")
        .version(crate_version!())
        .author("Erik Johnston <mxfedtest@jki.re>")
        .about("Bot to server diagnostic tool for Matrix federation")
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .arg(clap::Arg::with_name("CONFIG")
            .required(true)
        )
        .get_matches();

        let config : Config = {
            let mut f = File::open(matches.value_of("CONFIG").unwrap()).unwrap();
            let mut config_str = String::new();
            f.read_to_string(&mut config_str).unwrap();

            let mut parser = toml::Parser::new(&config_str);
            let value = match parser.parse() {
                Some(v) => v,
                None => {
                    panic!("{}", parser.errors[0]);
                }
            };
            let mut d = toml::Decoder::new(toml::Value::Table(value));
            serde::Deserialize::deserialize(&mut d).unwrap()
        };

        println!("Config: {:#?}", config);

        let mut client = hyper::Client::new();

        let mut next_batch = {
            let init_sync_url = format!(
                "{}/_matrix/client/r0/sync?access_token={}&timeout=30000",
                &config.server_url,
                &config.access_token,
            );
            let mut res = client.get(&init_sync_url).send().unwrap();
            let sync_response: SyncResponse = serde_json::from_reader(res).unwrap();
            sync_response.next_batch
        };

        println!("Started!");

        loop {
            let sync_url = format!(
                "{}/_matrix/client/r0/sync?access_token={}&since={}&timeout=30000",
                &config.server_url,
                &config.access_token,
                &next_batch,
            );

            let mut res = client.get(&sync_url).send().unwrap();
            let sync_response: SyncResponse = serde_json::from_reader(res).unwrap();

            handle_response(&sync_response, &client, &config);

            next_batch = sync_response.next_batch;
        }
}


fn handle_response(sync_response: &SyncResponse, client: &Client, config: &Config) {
    for (room_id, room) in &sync_response.rooms.join {
        for event in &room.timeline.events {
            handle_event(room_id, event, client, config);
        }
    }
}

fn handle_event(room_id: &str, event: &Event, client: &Client, config: &Config) {
    if event.event_type == "m.room.message" {
        if let Some(ref msgtype) = event.content.msgtype {
            if msgtype == "m.text" {
                if let Some(ref body) = event.content.body {
                    if body.starts_with("!mxfedtest ") {
                        let srv_name = &body[11..];

                        let res_opt = generate_report(srv_name.to_string(), &[IpAddr::from_str("8.8.8.8").unwrap()]);

                        if let Some(res) = res_opt {
                            let resp = format_response(&res);

                            let url = format!(
                                "{host}/_matrix/client/r0/rooms/{room_id}/send/m.room.message?access_token={token}",
                                host=&config.server_url,
                                room_id=&room_id,
                                token=&config.access_token
                            );

                            let content = EventContent {
                                msgtype: Some(String::from("m.text")),
                                format: Some(String::from("org.matrix.custom.html")),
                                formatted_body: Some(format!("<pre><code>{}</code></pre>", &resp)),
                                body: Some(String::from(resp)),
                            };

                            let mut send_resp = client.post(&url)
                                                  .body(&serde_json::to_vec(&content).unwrap()[..])
                                                  .header(ContentTypeHeader::json())
                                                  .send().unwrap();

                            let mut s = String::new();
                            send_resp.read_to_string(&mut s);
                            println!("{}", &s);
                        }
                    }
                }
            }
        }
    }
}

struct Response {
    resolve_result_map: mxfedtest::resolver::ResolveResultMap,
    connection_infos: Vec<mxfedtest::ConnectionInfo>,
    api_responses: Vec<ApiResponse>,
}

struct ApiResponse {
    host: String,
    key_response: mxfedtest::KeyApiResponse,
    server_header: String,
}


fn format_response(response: &Response) -> String {
    let mut output = String::new();

    for (query, res) in &response.resolve_result_map.srv_map {
        match *res {
            Ok(ref srv_results) => {
                for result in srv_results {
                    output.push_str(&format!(
                        "{}: {} {} {} {}\n",
                        &query,
                        result.priority,
                        result.weight,
                        &result.target,
                        result.port,
                    ));
                }
            },
            Err(ref e) => {
                output.push_str(&format!("{}: {}\n", &query, e));
            }
        }
    }

    output.push('\n');

    for (query, res) in &response.resolve_result_map.host_map {
        match *res {
            Ok(ref host_results) => {
                for host_result in host_results {
                    output.push_str(&format!(
                        "{}: {}\n",
                        &query,
                        match *host_result {
                            mxfedtest::resolver::HostResult::CNAME(ref target) => target as &Display,
                            mxfedtest::resolver::HostResult::IP(ref ip) => ip as &Display,
                        },
                    ));
                }
            },
            Err(ref e) => {
                output.push_str(&format!("{}: {}\n", &query, e));
            }
        }
    }

    output.push('\n');
    output.push('\n');

    for conn_info in &response.connection_infos {
        let split_fingerprint = conn_info.cert_info.cert_sha256.chunks(8)
            .map(|chunk| chunk.to_hex().to_uppercase())
            .collect::<Vec<String>>()
            .join("\n");

        output.push_str(&format!(
            "IP/Port: {} {}\nName: {}\nCertificate: {}\nCipher Name: {}\nVersion: {}\nBits: {}\n",
            &conn_info.ip, conn_info.port,
            &conn_info.server_name,
            &conn_info.cert_info.cert_sha256.to_hex().to_uppercase(),
            conn_info.cipher_name,
            conn_info.cipher_version,
            conn_info.cipher_bits
        ));

        output.push('\n');
    }

    output.push('\n');
    output.push('\n');

    for response in &response.api_responses {
        let vu = response.key_response.valid_until_ts;
        let date = NaiveDateTime::from_timestamp(
            (vu / 1000) as i64, ((vu % 1000) * 1000000) as u32
        );

        output.push_str(&format!(
            "IP/Port: {}\nServer Name: {}\nValid until: {}\nServer Header: {}\n",
            &response.host,
            &response.key_response.server_name,
            &date,
            &response.server_header,
        ));

        for (key_id, key) in &response.key_response.verify_keys {
            output.push_str(&format!("Verify key: {} {}\n", key_id, key.key));
        }

        for fingerprint in &response.key_response.tls_fingerprints {
            output.push_str(&format!(
                "TLS fingerprint: {}\n",
                &fingerprint.sha256.from_base64().unwrap().to_hex().to_uppercase()
            ));
        }

        output.push('\n');
    }

    output
}


fn generate_report(server_name: String, nameservers: &[IpAddr]) -> Option<Response> {
    let (srv_results_map, ip_ports) = mxfedtest::resolve_matrix_server(server_name.clone(), nameservers);

    if ip_ports.is_empty() {
        return None;
    }

    let mut server_responses = Vec::new();
    let mut conn_infos = Vec::new();

    for (_, _, port, ip) in ip_ports {
        match mxfedtest::get_ssl_info(
            &server_name,
            ip,
            port,
        ) {
            Ok((conn_info, server_response)) => {
                server_responses.push(((ip, port), server_response));
                conn_infos.push(conn_info);
            }
            Err(e) => {
                // TODO
            }
        }

    }

    let mut responses = Vec::new();

    for ((ip, port), server_response) in server_responses {
        let api_resp : mxfedtest::KeyApiResponse = serde_json::from_slice(
            &server_response.body
        ).unwrap();

        let formatted_host = match ip {
            IpAddr::V4(ref ipv4) => format!("{}:{}", ipv4, port),
            IpAddr::V6(ref ipv6) => format!("[{}]:{}", ipv6, port),
        };

        responses.push(ApiResponse {
            host: formatted_host,
            key_response: api_resp,
            server_header: server_response.server_header.unwrap_or_default(),
        });
    }

    Some(Response {
        resolve_result_map: srv_results_map,
        connection_infos: conn_infos,
        api_responses: responses,
    })
}
