#![feature(phase)]

extern crate libc;
extern crate regex;
#[phase(syntax)]
extern crate regex_macros;

use libc::{c_char, c_int, c_ushort};
use std::io::{Acceptor, Listener};
use std::io::{BufferedStream, TcpListener, TcpStream};
use std::str;

#[link(name = "identd_procfs")]
extern {
    fn lport_to_uid(port: c_ushort) -> c_int;
}

extern {
    fn getpwuid(uid: c_int) -> *passwd;
}

#[allow(non_camel_case_types)]
struct passwd {
    pw_name: *c_char,
    pw_passd: *c_char,
    pw_uid: c_int,
    pw_gid: c_int,
    pw_gecox: *c_char,
    pw_dir: *c_char,
    pw_shell: *c_char
}

fn handle_client(mut sock: TcpStream) {

    println!("Connection from {}.", sock.peer_name().unwrap());

    // So let's read in the request from the client
    let ref mut sock = BufferedStream::new(sock);
    let req = match sock.read_line() {
        Ok(buf) => buf,
        Err(e) => {
            println!("Couldn't read from stream: {}.", e);
            return;
        }
    };

    // Now we match against a regex for the right format
    let r = regex!("(?P<sport>[0-9]+)[ ]*,[ ]*(?P<cport>[0-9]+)");

    // Does the input match?
    match r.captures(req) {
        Some(caps) => {
            // Yes it does! Let's get the parts we want
            let sport: c_ushort = from_str(caps.name("sport")).unwrap();
            let cport: c_ushort = from_str(caps.name("cport")).unwrap();

            // Now let's find the user
            let uid = unsafe { lport_to_uid(sport) };
            if uid == -1 {
                println!("Couldn't find user mapped to port: {}.", sport);

                let _ = write!(sock, "{}, {} : ERROR : NO-USER", sport, cport);
                return;
            }

            let p = unsafe { getpwuid(uid) };
            if p.is_null() {
                println!("Couldn't map uid ({}) to passwd entry.", uid);

                let _ = write!(sock, "{}, {} : ERROR : UNKNOWN-ERROR", sport, cport);
                return;
            }

            let name = unsafe {
                str::raw::from_c_str((*p).pw_name)
            };

            // and write out the response, done!
            let _ = write!(sock, "{}, {} : USERID : UNIX : {}", sport, cport, name);
        }
        None => println!("Received badly formatted request.")
    }
}

fn main() {
    let addr = from_str("0.0.0.0:113").unwrap();
    let mut acceptor = match TcpListener::bind(addr).listen() {
        Ok(acceptor) => acceptor,
        Err(e) => fail!("Couldn't listen on {}: {}.", addr, e)
    };

    println!("Listening on {}.", addr);

    for stream in acceptor.incoming() {
        match stream {
            Ok(s) => spawn(proc() handle_client(s)),
            Err(e) => println!("Couldn't accept connection: {}.", e)
        }
    }
}
