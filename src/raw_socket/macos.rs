use crate::{cerr, interface::InterfaceName};

use super::RawSocket;

impl RawSocket {
    pub(crate) fn so_timestamp(&self, options: u32) -> std::io::Result<()> {
        // Documentation on the timestamping calls:
        //
        // - linux: https://www.kernel.org/doc/Documentation/networking/timestamping.txt
        // - freebsd: https://man.freebsd.org/cgi/man.cgi?setsockopt
        //
        // SAFETY:
        //
        // - the socket is provided by (safe) rust, and will outlive the call
        // - method is guaranteed to be a valid "name" argument
        // - the options pointer outlives the call
        // - the `option_len` corresponds with the options pointer
        //
        // Only some bits are valid to set in `options`, but setting invalid bits is
        // perfectly safe
        //
        // > Setting other bit returns EINVAL and does not change the current state.
        unsafe {
            cerr(libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMP,
                &options as *const _ as *const libc::c_void,
                std::mem::size_of_val(&options) as libc::socklen_t,
            ))
        }?;

        Ok(())
    }

    fn setsockopt_int(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> std::io::Result<()> {
        // Safety:
        // value lives for the duration of the call, and we pass its size
        // as option_len. setsockopt is safe to call in all other regards.
        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                level,
                name,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        })?;
        Ok(())
    }

    /// Restrict an IPv4 socket to `interface` (macOS equivalent of SO_BINDTODEVICE).
    pub(crate) fn bind_to_device(&self, interface: InterfaceName) -> std::io::Result<()> {
        let index = interface.index_or_err()?;
        self.setsockopt_int(libc::IPPROTO_IP, libc::IP_BOUND_IF, index as libc::c_int)
    }

    /// Restrict an IPv6 socket to `interface` (macOS equivalent of SO_BINDTODEVICE).
    pub(crate) fn bind_to_device_v6(&self, interface: InterfaceName) -> std::io::Result<()> {
        let index = interface.index_or_err()?;
        self.setsockopt_int(libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF, index as libc::c_int)
    }

    pub(crate) fn ip_multicast_if(&self, interface: InterfaceName) -> std::io::Result<()> {
        let addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(interface.ipv4_addr()?.octets()),
        };

        // Safety:
        // addr lives for the duration of the call, and we pass its size
        // as option_len. setsockopt is safe to call in all other regards
        cerr(unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
                libc::IP_MULTICAST_IF,
                &addr as *const _ as *const libc::c_void,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        })?;
        Ok(())
    }

    pub(crate) fn ipv6_multicast_if(&self, interface: InterfaceName) -> std::io::Result<()> {
        let index = interface.index_or_err()?;
        self.setsockopt_int(libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF, index as libc::c_int)
    }

    pub(crate) fn ip_multicast_loop(&self, enabled: bool) -> std::io::Result<()> {
        // macOS accepts either a u_char or an int for IP_MULTICAST_LOOP.
        self.setsockopt_int(libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, enabled as libc::c_int)
    }

    pub(crate) fn ipv6_multicast_loop(&self, enabled: bool) -> std::io::Result<()> {
        self.setsockopt_int(
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_LOOP,
            enabled as libc::c_int,
        )
    }

    pub(crate) fn ipv6_v6only(&self, enabled: bool) -> std::io::Result<()> {
        self.setsockopt_int(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, enabled as libc::c_int)
    }

    /// Allow several sockets (e.g. other PTP/Dante software) to bind the same port.
    pub(crate) fn reuse_port(&self) -> std::io::Result<()> {
        self.setsockopt_int(libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)
    }
}
