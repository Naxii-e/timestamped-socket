use std::{
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};

use tokio::io::unix::AsyncFd;

use crate::{
    interface::InterfaceName,
    networkaddress::{sealed::PrivateToken, NetworkAddress},
    raw_socket::RawSocket,
};

use super::{InterfaceTimestampMode, Open, Socket};

pub(super) fn configure_timestamping(
    socket: &RawSocket,
    _interface: Option<InterfaceName>,
    mode: InterfaceTimestampMode,
    _bind_phc: Option<u32>,
) -> std::io::Result<()> {
    match mode {
        InterfaceTimestampMode::None => Ok(()),
        InterfaceTimestampMode::SoftwareRecv => socket.so_timestamp(1),
        _ => Err(std::io::ErrorKind::Unsupported.into()),
    }
}

/// Open a UDP/IPv4 socket bound to `port` and restricted to `interface`.
///
/// `bind_phc` is ignored (no PHC on macOS). Only `None` and `SoftwareRecv`
/// timestamping are supported; other modes yield `ErrorKind::Unsupported`.
pub fn open_interface_udp4(
    interface: InterfaceName,
    port: u16,
    timestamping: InterfaceTimestampMode,
    bind_phc: Option<u32>,
) -> std::io::Result<Socket<SocketAddrV4, Open>> {
    // Setup the socket
    let socket = RawSocket::open(libc::PF_INET, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;
    socket.reuse_addr()?;
    socket.bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).to_sockaddr(PrivateToken))?;
    socket.bind_to_device(interface)?;
    socket.ip_multicast_if(interface)?;
    socket.ip_multicast_loop(false)?;
    configure_timestamping(&socket, Some(interface), timestamping, bind_phc)?;
    socket.set_nonblocking(true)?;

    Ok(Socket {
        timestamp_mode: timestamping,
        socket: AsyncFd::new(socket)?,
        _addr: PhantomData,
        _state: PhantomData,
    })
}

/// Open a UDP/IPv6 (v6only) socket bound to `port` and restricted to `interface`.
///
/// Same restrictions as [`open_interface_udp4`].
pub fn open_interface_udp6(
    interface: InterfaceName,
    port: u16,
    timestamping: InterfaceTimestampMode,
    bind_phc: Option<u32>,
) -> std::io::Result<Socket<SocketAddrV6, Open>> {
    // Setup the socket
    let socket = RawSocket::open(libc::PF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP)?;
    socket.reuse_addr()?;
    socket.ipv6_v6only(true)?;
    socket.bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).to_sockaddr(PrivateToken))?;
    socket.bind_to_device_v6(interface)?;
    socket.ipv6_multicast_if(interface)?;
    socket.ipv6_multicast_loop(false)?;
    configure_timestamping(&socket, Some(interface), timestamping, bind_phc)?;
    socket.set_nonblocking(true)?;

    Ok(Socket {
        timestamp_mode: timestamping,
        socket: AsyncFd::new(socket)?,
        _addr: PhantomData,
        _state: PhantomData,
    })
}
