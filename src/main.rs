use std::{
    cell::RefCell,
    cmp::min,
    env,
    net::{ToSocketAddrs, UdpSocket},
    process::exit,
    rc::Rc,
    thread::sleep,
    time::{Duration, Instant},
};

use test_client::{fmt_ms, SocketHandle, TurnClient};
use time::OffsetDateTime;

const CYCLES: u32 = 2;
const TIMEOUT: Duration = Duration::from_millis(400);
const PINGS_PER_ROUND: usize = 10;
const PING_SIZE: usize = 1200;

pub fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    let (server_a, user_a, pass_a, server_b, user_b, pass_b) = if args.len() == 4 {
        (
            args[1].to_owned(),
            args[2].to_owned(),
            args[3].to_owned(),
            args[1].to_owned(),
            args[2].to_owned(),
            args[3].to_owned(),
        )
    } else if args.len() == 7 {
        (
            args[1].to_owned(),
            args[2].to_owned(),
            args[3].to_owned(),
            args[4].to_owned(),
            args[5].to_owned(),
            args[6].to_owned(),
        )
    } else {
        println!("{} server user password [server user password]", args[0]);
        exit(1);
    };

    let client1 = UdpSocket::bind("0:0")?;
    let client2 = UdpSocket::bind("0:0")?;

    client1.set_read_timeout(Some(TIMEOUT))?;
    client2.set_read_timeout(Some(TIMEOUT))?;

    let client1 = Rc::new(RefCell::new(client1));
    let client2 = Rc::new(RefCell::new(client2));

    let addr_a = server_a
        .to_socket_addrs()
        .unwrap()
        .filter(|a| a.is_ipv4())
        .next()
        .unwrap();
    println!("turn a: {} ({})", server_a, addr_a);
    let turn_a = Rc::new(RefCell::new(TurnClient::new(
        SocketHandle::Udp(client1.clone()),
        addr_a,
        &user_a,
        &pass_a,
    )));
    turn_a.borrow_mut().allocate()?;

    let addr_b = server_b
        .to_socket_addrs()
        .unwrap()
        .filter(|a| a.is_ipv4())
        .next()
        .unwrap();
    println!("turn b: {} ({})", server_b, addr_b);
    let turn_b = Rc::new(RefCell::new(TurnClient::new(
        SocketHandle::Udp(client2.clone()),
        addr_b,
        &user_b,
        &pass_b,
    )));
    turn_b.borrow_mut().allocate()?;

    let client2_reflexive = turn_b.borrow().reflexive_addr.unwrap();
    println!("client 2 reflexive {:?} relay {:?}", client2_reflexive, turn_b.borrow().relay_addr.unwrap());

    let client1_reflexive = turn_a.borrow().reflexive_addr.unwrap();
    println!("client 1 reflexive {:?} relay {:?}", client1_reflexive, turn_a.borrow().relay_addr.unwrap());

    // allow for client1 -> turn A -> turn B -> client2 and vice versa
    turn_a
        .borrow_mut()
        .add_permission(turn_b.borrow().relay_addr.unwrap())?;
    turn_b
        .borrow_mut()
        .add_permission(turn_a.borrow().relay_addr.unwrap())?;

    // client1 -> A -> B -> client2
    let mut min_c_a_b_c = Duration::MAX;
    let mut count_c_a_b_c = 0;

    // client1 -> B -> A -> client1
    let mut min_c_b_a_c = Duration::MAX;
    let mut count_c_b_a_c = 0;

    for _ in 0..CYCLES {
        // client -> turn a -> turn b -> client
        if let Ok((time, _peer_observed)) = turn_a.borrow().relay_to_client(&turn_b.borrow()) {
            min_c_a_b_c = min(min_c_a_b_c, time);
            count_c_a_b_c += 1;
        }

        // client -> turn b -> turn a -> client
        if let Ok((time, _peer_observed)) = turn_b.borrow().relay_to_client(&turn_a.borrow()) {
            min_c_b_a_c = min(min_c_b_a_c, time);
            count_c_b_a_c += 1;
        }
    }
    println!(
        "client1 -> turn a -> turn b -> client2:         ({})  {}",
        count_c_a_b_c,
        fmt_ms(min_c_a_b_c)
    );
    println!(
        "client2 -> turn b -> turn a -> client1:         ({})  {}",
        count_c_b_a_c,
        fmt_ms(min_c_b_a_c)
    );

    if count_c_a_b_c == 0 {
        println!("can't demo phase 2, no working turn");

        return Ok(());
    }

    println!("\n\ntest random sized packets");
    println!("inbound pings  are client2 -> turn b -> turn a -> client1");

    println!("outbound pings are client1 -> turn a -> turn b -> client2");

    println!("packet counts are short long matched duplicate unknown / sent");

    let mut inbound_short = 0;
    let mut inbound_long = 0;
    let mut inbound_matched = 0;
    let mut inbound_duplicate = 0;
    let mut inbound_unknown = 0;

    let mut outbound_short = 0;
    let mut outbound_long = 0;
    let mut outbound_matched = 0;
    let mut outbound_duplicate = 0;
    let mut outbound_unknown = 0;

    let mut sent = 0;

    let start = Instant::now();
    let mut last_refresh = start;
    let mut last_output = start;

    loop {
        let now = Instant::now();
        let will_stop = now.duration_since(start) > Duration::from_secs(10);

        if now.duration_since(last_output) > Duration::from_secs(1) || will_stop {
            let utc = OffsetDateTime::now_utc();
            let (h, m, s) = utc.to_hms();
            println!(
                "{:02}:{:02}:{:02} inbound pings {} {} {} {} {} /{}; outbound pings {} {} {} {} {}/{}",
                h, m, s, inbound_short, inbound_long, inbound_matched, inbound_duplicate, inbound_unknown, sent,
                outbound_short, outbound_long, outbound_matched, outbound_duplicate, outbound_unknown,
                sent,
            );
            inbound_short = 0;
            inbound_long = 0;
            inbound_matched = 0;
            inbound_duplicate = 0;
            inbound_unknown = 0;

            outbound_short = 0;
            outbound_long = 0;
            outbound_matched = 0;
            outbound_duplicate = 0;
            outbound_unknown = 0;
            sent = 0;
            last_output = now;
        }

        if will_stop {
            break;
        }

        if now.duration_since(last_refresh) > Duration::from_secs(60) {
            last_refresh = now;
            println!("refreshing allocation permissions");

            turn_b.borrow_mut().refresh()?;
            turn_a
                .borrow_mut()
                .add_permission(turn_b.borrow().relay_addr.unwrap())?;
            turn_b
                .borrow_mut()
                .add_permission(turn_a.borrow().relay_addr.unwrap())?;
        }

        let (short, long, matched, duplicate, unknown) =
            turn_b
                .borrow()
                .relay_to_client_multiple(&turn_a.borrow(), PINGS_PER_ROUND, PING_SIZE);
        inbound_short += short;
        inbound_long += long;
        inbound_matched += matched;
        inbound_duplicate += duplicate;
        inbound_unknown += unknown;

        let (short, long, matched, duplicate, unknown) =
            turn_a
                .borrow()
                .relay_to_client_multiple(&turn_b.borrow(), PINGS_PER_ROUND, PING_SIZE);
        outbound_short += short;
        outbound_long += long;
        outbound_matched += matched;
        outbound_duplicate += duplicate;
        outbound_unknown += unknown;

        sent += PINGS_PER_ROUND;
        sleep(Duration::from_millis(10)); // sleep here to reduce maximum traffic
    }

    Ok(())
}
