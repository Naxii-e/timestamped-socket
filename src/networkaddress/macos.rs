use std::{
    net::{SocketAddrV4, SocketAddrV6},
    os::fd::RawFd,
};

use crate::{cerr, interface::InterfaceName};

use super::{
    sealed::{PrivateToken, SealedMC},
    MulticastJoinable,
};

fn ip_mreq(group: &SocketAddrV4, interface: InterfaceName) -> std::io::Result<libc::ip_mreq> {
    Ok(libc::ip_mreq {
        imr_multiaddr: libc::in_addr {
            s_addr: u32::from_ne_bytes(group.ip().octets()),
        },
        imr_interface: libc::in_addr {
            s_addr: u32::from_ne_bytes(interface.ipv4_addr()?.octets()),
        },
    })
}

fn ipv6_mreq(group: &SocketAddrV6, interface: InterfaceName) -> std::io::Result<libc::ipv6_mreq> {
    Ok(libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr {
            s6_addr: group.ip().octets(),
        },
        ipv6mr_interface: interface.index_or_err()?,
    })
}

fn setsockopt<T>(
    socket: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: &T,
) -> std::io::Result<()> {
    // Safety:
    // value points to a struct of length option_len, of the type expected for
    // the given level/name (callers pass ip_mreq / ipv6_mreq only).
    cerr(unsafe {
        libc::setsockopt(
            socket,
            level,
            name,
            value as *const T as *const libc::c_void,
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    })?;
    Ok(())
}

impl SealedMC for SocketAddrV4 {}

impl MulticastJoinable for SocketAddrV4 {
    fn join_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()> {
        let request = ip_mreq(self, interface)?;
        setsockopt(socket, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, &request)
    }

    fn leave_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()> {
        let request = ip_mreq(self, interface)?;
        setsockopt(socket, libc::IPPROTO_IP, libc::IP_DROP_MEMBERSHIP, &request)
    }
}

impl SealedMC for SocketAddrV6 {}

impl MulticastJoinable for SocketAddrV6 {
    fn join_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()> {
        let request = ipv6_mreq(self, interface)?;
        setsockopt(socket, libc::IPPROTO_IPV6, libc::IPV6_JOIN_GROUP, &request)
    }

    fn leave_multicast(
        &self,
        socket: RawFd,
        interface: InterfaceName,
        _token: PrivateToken,
    ) -> std::io::Result<()> {
        let request = ipv6_mreq(self, interface)?;
        setsockopt(socket, libc::IPPROTO_IPV6, libc::IPV6_LEAVE_GROUP, &request)
    }
}
