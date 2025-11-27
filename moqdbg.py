#!/usr/bin/env python3
"""
MoQ Debug Tool: Like curl for Media over QUIC with headers, timings, packet loss, buffer, RTT, jitter.
Usage: python moqdbg.py [options]
Supports: announce (publish), join (subscribe), headers-only (-I).
Verbose: QUIC events, frames, varints. Stats: timings, loss, buffer, RTT, jitter.
Based on MoQ draft: binary framing over QUIC streams.

TLS: Uses certifi for bundled CA certs (browser-like). Use --ignore-cert to bypass verification.
"""

import argparse
import asyncio
import logging
import sys
import time
from typing import Optional, Dict, Any, List
import ssl
import os
import socket
import certifi

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, StreamReset, ProtocolNegotiated

# MoQ Varint helpers
def encode_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    elif value < 0x2000:
        return bytes([(value >> 6) | 0x80, value & 0x3F])
    b = bytearray()
    while True:
        b.append(value & 0x7F)
        value >>= 7
        if value == 0:
            break
        b[-1] |= 0x80
    b.reverse()
    return bytes(b)

def decode_varint(data: bytes, pos: int = 0) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        pos += 1
        if (byte & 0x80) == 0:
            break
        shift += 7
    return value, pos

# MoQ Message Types
MOQ_MESSAGE_JOIN = 0x01
MOQ_MESSAGE_ANNOUNCE = 0x02
MOQ_MESSAGE_HEADERS = 0x03
MOQ_MESSAGE_FRAME = 0x04
MOQ_MESSAGE_ANNOUNCE_OK = 0x05
MOQ_MESSAGE_ANNOUNCE_ERROR = 0x06

class MoQProtocol(QuicConnectionProtocol):
    def __init__(self, *args, headers_only: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.streams: Dict[int, Dict[str, Any]] = {}
        self.logger = logging.getLogger("MoQ")
        self.headers_only = headers_only
        self.stats = {
            'connect_time': None,
            'first_frame_time': None,
            'packets_sent': 0,
            'packets_lost': 0,
            'buffer_size': 0,
            'rtt': 0.0,
            'frame_arrival_times': []
        }

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        if transport is None:
            self.logger.error(f"Transport is None in connection_made - event loop: {asyncio.get_event_loop()}")
            raise RuntimeError("Failed to initialize transport - possible TLS, ALPN, or server issue")
        self.logger.debug(f"Asyncio connection made with transport: {type(transport).__name__}, event loop: {asyncio.get_event_loop()}")
        self.stats['connect_time'] = time.time()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated):
            self.logger.debug(f"QUIC protocol negotiated at {self.stats['connect_time']:.3f}s (ALPN: {event.alpn_protocol})")
        elif isinstance(event, StreamDataReceived):
            current_time = time.time()
            if not self.stats['first_frame_time']:
                self.stats['first_frame_time'] = current_time
            self.stats['frame_arrival_times'].append(current_time)
            self.handle_moq_message(event.stream_id, event.data)
        elif isinstance(event, StreamReset):
            self.logger.warning(f"Stream {event.stream_id} reset: {event.error_code}")
            print(f"Stream {event.stream_id} interrupted. Possible stream termination.")

    def update_stats(self):
        try:
            quic_stats = self._quic.get_stats()
            self.stats['packets_sent'] = quic_stats.get('sent_packets', 0)
            self.stats['packets_lost'] = quic_stats.get('lost_packets', 0)
            self.stats['buffer_size'] = self._quic.get_send_window()
            self.stats['rtt'] = quic_stats.get('smoothed_rtt', 0.0) * 1000  # Convert to ms
            if len(self.stats['frame_arrival_times']) > 1:
                inter_arrivals = [
                    self.stats['frame_arrival_times'][i] - self.stats['frame_arrival_times'][i-1]
                    for i in range(1, len(self.stats['frame_arrival_times']))
                ]
                mean = sum(inter_arrivals) / len(inter_arrivals)
                variance = sum((x - mean) ** 2 for x in inter_arrivals) / len(inter_arrivals)
                self.stats['jitter'] = variance ** 0.5 * 1000  # Convert to ms
            else:
                self.stats['jitter'] = 0.0
        except Exception as e:
            self.logger.error(f"Error updating stats: {e}")

    def handle_moq_message(self, stream_id: int, data: bytes) -> None:
        pos = 0
        while pos < len(data):
            try:
                msg_type, pos = decode_varint(data, pos)
                length, pos = decode_varint(data, pos)
                payload = data[pos:pos + length]
                pos += length

                if msg_type == MOQ_MESSAGE_HEADERS:
                    headers = payload.decode('utf-8', errors='ignore').split()
                    print(f"Headers (stream {stream_id}):")
                    for header in headers:
                        print(f"  {header}")
                elif msg_type == MOQ_MESSAGE_ANNOUNCE_OK:
                    print(f"ANNOUNCE_OK (stream {stream_id}): {payload.decode('utf-8', errors='ignore')}")
                elif msg_type == MOQ_MESSAGE_ANNOUNCE_ERROR:
                    print(f"ANNOUNCE_ERROR (stream {stream_id}): {payload.decode('utf-8', errors='ignore')}")
                elif msg_type == MOQ_MESSAGE_FRAME and not self.headers_only:
                    print(f"Media Frame (stream {stream_id}, {len(payload)} bytes): {payload.hex()[:50]}...")
                    try:
                        print(f"  Content: {payload.decode('utf-8')[:100]}")
                    except UnicodeDecodeError:
                        pass
                else:
                    self.logger.debug(f"Unknown msg type {msg_type} on {stream_id}")

                if self.headers_only:
                    break
            except Exception as e:
                self.logger.error(f"Error parsing message on stream {stream_id}: {e}")
                break

    def send_control_message(self, stream_id: int, msg_type: int, payload: bytes = b"") -> None:
        try:
            msg = encode_varint(msg_type) + encode_varint(len(payload)) + payload
            self._quic.send_stream_data(stream_id, msg)
            self.logger.debug(f"TX Control {msg_type} on {stream_id}: {msg.hex()}")
        except Exception as e:
            self.logger.error(f"Failed to send control message on {stream_id}: {e}")

    def send_media_frame(self, stream_id: int, frame: bytes) -> None:
        try:
            msg = encode_varint(MOQ_MESSAGE_FRAME) + encode_varint(len(frame)) + frame
            self._quic.send_stream_data(stream_id, msg)
            self.logger.debug(f"TX Frame on {stream_id} ({len(frame)} bytes)")
        except Exception as e:
            self.logger.error(f"Failed to send media frame on {stream_id}: {e}")

    def get_next_available_stream_id(self, is_unidirectional: bool = False) -> int:
        try:
            return self._quic.get_next_available_stream_id(is_unidirectional)
        except Exception as e:
            self.logger.error(f"Error getting stream ID: {e}")
            raise

async def run_moq(host: str, port: int, action: str, resource: Optional[str] = None,
                  media_file: Optional[str] = None, headers_only: bool = False,
                  verbose: bool = False, stats: bool = False, alpn: Optional[str] = None,
                  ignore_cert: bool = False, retries: int = 3) -> None:
    start_time = time.time()
    alpn_protocols = [alpn] if alpn else ["moq-00", "moq-01", "h3", "moq-lite", "moq"]
    for attempt in range(1, retries + 1):
        configuration = QuicConfiguration(
            alpn_protocols=alpn_protocols,
            is_client=True,
            verify_mode=ssl.CERT_NONE if ignore_cert else ssl.CERT_REQUIRED
        )
        if not ignore_cert:
            configuration.load_verify_locations(cafile=certifi.where())
            print(f"Attempt {attempt}/{retries}: Using certifi CA bundle for server verification")
        else:
            print(f"Attempt {attempt}/{retries}: Ignoring certificate verification (--ignore-cert)")

        # Test UDP socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.connect((host, port))
            sock.close()
            print(f"Attempt {attempt}/{retries}: UDP socket test to {host}:{port} succeeded")
        except Exception as e:
            print(f"Attempt {attempt}/{retries}: UDP socket test failed: {e}")
            logging.error(f"UDP socket error: {e}")
            if attempt == retries:
                print("All UDP tests failed. Check network connectivity (UDP/443) or firewall.")
                return
            continue

        try:
            async with connect(
                host=host,
                port=port,
                configuration=configuration,
                create_protocol=lambda *args, **kwargs: MoQProtocol(*args, headers_only=headers_only, **kwargs)
            ) as protocol:
                try:
                    control_stream = protocol.get_next_available_stream_id(is_unidirectional=False)
                    print(f"Attempt {attempt}/{retries}: Connected to {host}:{port} via QUIC (Control Stream: {control_stream})")
                except Exception as e:
                    print(f"Attempt {attempt}/{retries}: Failed to initialize control stream: {e}")
                    logging.error(f"Control stream error: {e}")
                    if attempt == retries:
                        print("All attempts failed to initialize control stream.")
                    continue

                if verbose:
                    logging.basicConfig(level=logging.DEBUG)

                # Try provided resource, fall back to /watch if it fails
                active_resource = resource
                try:
                    if action == "announce" and resource:
                        announce_payload = f"broadcast:{resource}".encode()
                        protocol.send_control_message(control_stream, MOQ_MESSAGE_ANNOUNCE, announce_payload)
                        if media_file and not headers_only:
                            try:
                                with open(media_file, 'rb') as f:
                                    while chunk := f.read(1024):
                                        protocol.send_media_frame(control_stream, chunk)
                                        protocol.update_stats()
                                        if stats:
                                            print(f"Stats: Sent {protocol.stats['packets_sent']} packets, "
                                                  f"Lost {protocol.stats['packets_lost']}, "
                                                  f"Buffer {protocol.stats['buffer_size']} bytes, "
                                                  f"RTT {protocol.stats['rtt']:.2f} ms, "
                                                  f"Jitter {protocol.stats['jitter']:.2f} ms")
                            except FileNotFoundError:
                                print(f"Error: Media file {media_file} not found.")
                                return
                    elif action == "join" and resource:
                        join_payload = f"resource:{resource}".encode()
                        protocol.send_control_message(control_stream, MOQ_MESSAGE_JOIN, join_payload)
                        headers = b"track:video codec:h264 profile:main"
                        protocol.send_control_message(control_stream, MOQ_MESSAGE_HEADERS, headers)
                        try:
                            await asyncio.sleep(30 if not headers_only else 5)
                        except asyncio.CancelledError:
                            print("Stream interrupted by user (Ctrl+C).")
                            return
                    else:
                        print("No/invalid action. Use --announce or --join with --resource.")
                        return
                except Exception as e:
                    if resource != "/watch":
                        print(f"Attempt {attempt}/{retries}: Resource {resource} failed: {e}. Falling back to /watch")
                        logging.error(f"Resource {resource} error: {e}")
                        active_resource = "/watch"
                        join_payload = f"resource:{active_resource}".encode()
                        protocol.send_control_message(control_stream, MOQ_MESSAGE_JOIN, join_payload)
                        headers = b"track:video codec:h264 profile:main"
                        protocol.send_control_message(control_stream, MOQ_MESSAGE_HEADERS, headers)
                        try:
                            await asyncio.sleep(30 if not headers_only else 5)
                        except asyncio.CancelledError:
                            print("Stream interrupted by user (Ctrl+C).")
                            return

                if stats:
                    protocol.update_stats()
                    connect_duration = (protocol.stats['connect_time'] - start_time) * 1000 if protocol.stats['connect_time'] else 0
                    transfer_duration = (protocol.stats['first_frame_time'] - protocol.stats['connect_time']) * 1000 if protocol.stats['first_frame_time'] else 0
                    print(f"\nNetwork Stats for {active_resource}:")
                    print(f"  Connection Time: {connect_duration:.2f} ms")
                    print(f"  First Frame Time: {transfer_duration:.2f} ms")
                    print(f"  Packets Sent: {protocol.stats['packets_sent']}")
                    print(f"  Packets Lost: {protocol.stats['packets_lost']}")
                    print(f"  Buffer Available: {protocol.stats['buffer_size']} bytes")
                    print(f"  RTT: {protocol.stats['rtt']:.2f} ms")
                    print(f"  Jitter: {protocol.stats['jitter']:.2f} ms")
                return  # Success, exit retry loop

        except ssl.SSLError as e:
            print(f"Attempt {attempt}/{retries}: TLS handshake failed: {e}")
            logging.error(f"TLS error: {e}")
            if ignore_cert:
                print("Ignoring TLS error due to --ignore-cert")
            else:
                print("Run: openssl s_client -connect moq.dev:443 -alpn moq-00")
                print("Or use --ignore-cert to bypass certificate verification")
                if attempt == retries:
                    print(f"All {retries} attempts failed due to TLS issues.")
                else:
                    print(f"Retrying in 2 seconds...")
                    await asyncio.sleep(2)
        except Exception as e:
            print(f"Attempt {attempt}/{retries}: Connection failed: {e}")
            logging.error(f"Connection error: {e}")
            if "NoneType" in str(e):
                print("Transport initialization failed. Run: nc -u -z moq.dev 443 (already succeeded)")
                print("Try: python3 moqdbg.py moq.dev -p 443 -a join -r '/watch' -v -s")
                print("Test ALPN: openssl s_client -connect moq.dev:443 -alpn moq-lite")
            elif "connection refused" in str(e).lower():
                print("Server may be down or rejecting ALPN. Check moq.dev status.")
            if attempt == retries:
                print(f"All {retries} connection attempts failed.")
            else:
                print(f"Retrying in 2 seconds...")
                await asyncio.sleep(2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MoQ Debug Tool")
    parser.add_argument("host", help="MoQ server/relay host (e.g., moq.dev)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port (default 443 for QUIC)")
    parser.add_argument("-a", "--action", choices=["announce", "join"], required=True,
                        help="Action: announce (publish) or join (subscribe)")
    parser.add_argument("-r", "--resource", help="Broadcast resource (e.g., /watch?name=tasty-emu)")
    parser.add_argument("-f", "--file", help="Media file to publish (for announce)")
    parser.add_argument("-I", "--headers", action="store_true", help="Show headers only (like curl -I)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-s", "--stats", action="store_true", help="Show timings, loss, buffer, RTT, jitter")
    parser.add_argument("--alpn", help="Custom ALPN (e.g., moq-lite)")
    parser.add_argument("--ignore-cert", action="store_true", help="Ignore certificate verification errors")

    args = parser.parse_args()

    if (args.action == "announce" and not args.resource) or (args.action == "join" and not args.resource):
        print(f"{args.action.title()} requires --resource")
        sys.exit(1)

    asyncio.run(run_moq(args.host, args.port, args.action, args.resource, args.file,
                        args.headers, args.verbose, args.stats, args.alpn, args.ignore_cert))
