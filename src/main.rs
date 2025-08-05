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
    } else if args.len() == 5 {
        (
            args[1].to_owned(),
            args[2].to_owned(),
            args[3].to_owned(),
            "".to_owned(),
            "".to_owned(),
            "".to_owned(),
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

    let client1 = Rc::new(RefCell::new((None, client1)));
    let client2 = Rc::new(RefCell::new((None, client2)));

    let addr_a = server_a
        .to_socket_addrs()
        .unwrap()
        .filter(|a| a.is_ipv4())
        .next()
        .unwrap();
    println!("turn a: {} ({})", server_a, addr_a);
    let turn_a = SocketHandle::Turn(Rc::new(RefCell::new(TurnClient::new(
        SocketHandle::Udp(client1.clone()),
        addr_a,
        &user_a,
        &pass_a,
    ))));
    turn_a.allocate()?;

    let (turn_b, client_1_2_path, client_2_1_path) = if server_b != "" {
        let addr_b = server_b
            .to_socket_addrs()
            .unwrap()
            .filter(|a| a.is_ipv4())
            .next()
            .unwrap();
        println!("turn b: {} ({})", server_b, addr_b);
        let turn_b = SocketHandle::Turn(Rc::new(RefCell::new(TurnClient::new(
            SocketHandle::Udp(client2.clone()),
            addr_b,
            &user_b,
            &pass_b,
        ))));
        turn_b.allocate()?;

        let client2_reflexive = turn_b.reflexive_addr().unwrap();
        println!(
            "client 2 reflexive {:?} relay {:?}",
            client2_reflexive,
            turn_b.relay_addr().unwrap()
        );
        (
            turn_b,
            "client1 (TURN) -> turn a -> (relay) turn b -> (TURN) client2",
            "client2 (TURN) -> turn b -> (relay) turn a -> (TURN) client1",
        )
    } else {
        turn_a.add_permission(turn_a.reflexive_addr().unwrap())?;

        let handle = SocketHandle::Udp(client2);

        let (_duration, addr) = turn_a.send_from_peer(&handle).unwrap();
        println!("peer address {} ", addr);
        handle.set_relay_addr(addr);
        (
            handle,
            "client1 (TURN)  -> turn a -> (relay)   peer",
            "peer    (relay) -> turn a -> (TURN) client1",
        )
    };

    let client1_reflexive = turn_a.reflexive_addr().unwrap();
    println!(
        "client 1 reflexive {:?} relay {:?}",
        client1_reflexive,
        turn_a.relay_addr().unwrap()
    );

    // allow for client1 -> turn A -> turn B -> client2 and vice versa
    turn_a.add_permission(turn_b.relay_addr().unwrap())?;
    turn_b.add_permission(turn_a.relay_addr().unwrap())?;

    // client1 -> A -> B -> client2
    let mut min_c_a_b_c = Duration::MAX;
    let mut count_c_a_b_c = 0;

    // client1 -> B -> A -> client1
    let mut min_c_b_a_c = Duration::MAX;
    let mut count_c_b_a_c = 0;

    for _ in 0..CYCLES {
        // client -> turn a -> turn b -> client
        if let Ok((time, _peer_observed)) = turn_a.relay_to_client(&turn_b) {
            min_c_a_b_c = min(min_c_a_b_c, time);
            count_c_a_b_c += 1;
        }

        // client -> turn b -> turn a -> client
        if let Ok((time, _peer_observed)) = turn_b.relay_to_client(&turn_a) {
            min_c_b_a_c = min(min_c_b_a_c, time);
            count_c_b_a_c += 1;
        }
    }
    println!(
        "test ping {}:         ({}/{})  {} ms",
        client_1_2_path,
        count_c_a_b_c,
        CYCLES,
        fmt_ms(min_c_a_b_c)
    );
    println!(
        "test ping {}:         ({}/{})  {} ms",
        client_2_1_path,
        count_c_b_a_c,
        CYCLES,
        fmt_ms(min_c_b_a_c)
    );

    if count_c_a_b_c == 0 {
        println!("can't demo phase 2, no working turn");

        return Ok(());
    }

    println!("\n\ntest random sized packets");
    println!("inbound pings  are {}", client_2_1_path);
    println!("outbound pings are {}", client_1_2_path);

    println!("time, sent, recv / recv-err / loss %"); // , rtt min / avg / max / stddev, throughput");

    let mut inbound_sent = 0;
    let mut inbound_recv = 0;
    let mut inbound_recv_err = 0;
    let mut inbound_rtts = vec![];

    let mut outbound_sent = 0;
    let mut outbound_recv = 0;
    let mut outbound_recv_err = 0;
    let mut outbound_rtts = vec![];

    let start = Instant::now();
    let mut last_refresh = start;
    let mut last_output = start;

    loop {
        let now = Instant::now();
        let will_stop = now.duration_since(start) > Duration::from_secs(600);

        if now.duration_since(last_output) > Duration::from_secs(1)
            || will_stop && (inbound_sent != 0 && outbound_sent != 0)
        {
            let utc = OffsetDateTime::now_utc();
            let (h, m, s) = utc.to_hms();

            //let (inbound_min, inbound_max, inbound_avg, inbound_dev) = ("?", "?", "?", "?");
            //let (outbound_min, outbound_max, outbound_avg, outbound_dev) = ("?", "?", "?", "?");

            println!(
                concat!(
                    "{:02}:{:02}:{:02} inbound pings {}, {} / {} / {}%",
                    //, {} / {} / {} / {}, {}
                    "; outbound pings {}, {} / {} / {}%",
                    //", {} / {} / {} / {}, {}"
                ),
                h,
                m,
                s,
                inbound_sent,
                inbound_recv,
                inbound_recv_err,
                100 * (inbound_sent - inbound_recv) / inbound_sent,
                //inbound_min, inbound_avg, inbound_max, inbound_dev, "?",
                outbound_sent,
                outbound_recv,
                outbound_recv_err,
                100 * (outbound_sent - outbound_recv) / outbound_sent,
                // outbound_min, outbound_avg, outbound_max, outbound_dev, "?",
            );

            inbound_sent = 0;
            inbound_recv = 0;
            inbound_recv_err = 0;
            inbound_rtts = vec![];

            outbound_sent = 0;
            outbound_recv = 0;
            outbound_recv_err = 0;
            outbound_rtts = vec![];

            last_output = now;
        }

        if will_stop {
            break;
        }

        if now.duration_since(last_refresh) > Duration::from_secs(60) {
            last_refresh = now;
            println!("refreshing allocation permissions");

            turn_b.refresh()?;
            turn_a.add_permission(turn_b.relay_addr().unwrap())?;
            turn_b.add_permission(turn_a.relay_addr().unwrap())?;
        }

        let (sent, recv, recv_err, mut rtts) =
            turn_b.relay_to_client_multiple(&turn_a, PINGS_PER_ROUND, PING_SIZE);

        inbound_sent += sent;
        inbound_recv += recv;
        inbound_recv_err += recv_err;
        inbound_rtts.append(&mut rtts);

        let (sent, recv, recv_err, mut rtts) =
            turn_a.relay_to_client_multiple(&turn_b, PINGS_PER_ROUND, PING_SIZE);

        outbound_sent += sent;
        outbound_recv += recv;
        outbound_recv_err += recv_err;
        outbound_rtts.append(&mut rtts);

        sleep(Duration::from_millis(10)); // sleep here to reduce maximum traffic
    }

    Ok(())
}
