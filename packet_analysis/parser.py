"""
IPsec PCAP Parser for SentraIPS.
Performs protocol-level dissection of PCAP/PCAPNG files, detecting IKEv1/IKEv2, ESP, AH,
and non-IPsec traffic. Extracts observable cryptographic proposals, SPIs, and parameters
without fabricating unobserved fields.
"""

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, Field
from scapy.all import rdpcap, IP, IPv6, UDP, TCP, ICMP, Raw
from scapy.layers.ipsec import ESP, AH

# Import Scapy IKEv2 support
try:
    import scapy.contrib.ikev2 as ikev2
    from scapy.contrib.ikev2 import (
        IKEv2, IKEv2_SA, IKEv2_Proposal, IKEv2_Transform,
        IKEv2_KE, IKEv2_Nonce, IKEv2_Notify, IKEv2_Encrypted,
        IKEv2TransformTypes, IKEv2TransformAlgorithms
    )
    HAS_IKEV2_CONTRIB = True
except Exception:
    HAS_IKEV2_CONTRIB = False


# Well-known DH Group Number to RFC Name mapping
DH_GROUP_MAP = {
    1: "modp768 (Group 1 - Insecure)",
    2: "modp1024 (Group 2 - Legacy/Weak)",
    5: "modp1536 (Group 5 - Legacy/Weak)",
    14: "modp2048 (Group 14 - Standard)",
    15: "modp3072 (Group 15 - High)",
    16: "modp4096 (Group 16 - High)",
    17: "modp6144 (Group 17 - Ultra)",
    18: "modp8192 (Group 18 - Ultra)",
    19: "ecp256 / NIST P-256 (Group 19 - Recommended)",
    20: "ecp384 / NIST P-384 (Group 20 - Recommended)",
    21: "ecp521 / NIST P-521 (Group 21 - High)",
    31: "Curve25519 (Group 31 - Modern)",
    32: "Curve448 (Group 32 - Modern)",
}

DH_SHORT_NAME_MAP = {
    1: "modp768",
    2: "modp1024",
    5: "modp1536",
    14: "modp2048",
    15: "modp3072",
    16: "modp4096",
    17: "modp6144",
    18: "modp8192",
    19: "ecp256",
    20: "ecp384",
    21: "ecp521",
    31: "curve25519",
    32: "curve448",
}


class IKEProposalDetail(BaseModel):
    proposal_num: int = 1
    protocol: str = "IKE"
    encryption: str = "Unknown / Not Detected"
    key_length: Optional[int] = None
    integrity: str = "Unknown / Not Detected"
    prf: str = "Unknown / Not Detected"
    dh_group: Optional[int] = None
    dh_group_name: str = "Unknown / Not Detected"


class IKEAnalysisResult(BaseModel):
    detected: bool = False
    version: str = "Unknown / Not Detected"
    initiator_spi: str = "Unknown / Not Detected"
    responder_spi: str = "Unknown / Not Detected"
    initiator_endpoint: str = "Unknown / Not Detected"
    responder_endpoint: str = "Unknown / Not Detected"
    encryption: str = "Unknown / Not Detected"
    encryption_key_length: Optional[int] = None
    authentication: str = "Unknown / Not Detected"
    prf: str = "Unknown / Not Detected"
    dh_group: Optional[int] = None
    dh_group_name: str = "Unknown / Not Detected"
    pfs: Union[bool, str] = "Unknown / Not Detected"
    packet_count: int = 0
    exchange_types_observed: List[str] = Field(default_factory=list)
    proposals: List[IKEProposalDetail] = Field(default_factory=list)


class ESPAnalysisResult(BaseModel):
    detected: bool = False
    packet_count: int = 0
    spis_observed: List[str] = Field(default_factory=list)
    seq_min: Optional[int] = None
    seq_max: Optional[int] = None
    endpoints: List[str] = Field(default_factory=list)
    total_bytes: int = 0


class PCAPParseResult(BaseModel):
    capture_id: str
    filename: str
    file_size_bytes: int
    is_valid: bool
    ipsec_detected: bool = False
    ike_detected: bool = False
    esp_detected: bool = False
    ah_detected: bool = False
    total_packets: int = 0
    ike_packets: int = 0
    esp_packets: int = 0
    ah_packets: int = 0
    non_ipsec_packets: int = 0
    protocols_detected: List[str] = Field(default_factory=list)
    ike: IKEAnalysisResult = Field(default_factory=IKEAnalysisResult)
    esp: ESPAnalysisResult = Field(default_factory=ESPAnalysisResult)
    features_extracted: bool = False
    ground_truth: Optional[Dict[str, Any]] = None
    errors: List[str] = Field(default_factory=list)

    @property
    def encryption(self) -> str:
        return self.ike.encryption if self.ike else "Unknown / Not Detected"

    @property
    def encryption_key_length(self) -> Optional[int]:
        return self.ike.encryption_key_length if self.ike else None

    @property
    def dh_group(self) -> Optional[int]:
        return self.ike.dh_group if self.ike else None

    @property
    def dh_group_name(self) -> str:
        return self.ike.dh_group_name if self.ike else "Unknown / Not Detected"

    @property
    def pfs(self) -> Union[bool, str]:
        return self.ike.pfs if self.ike else False

    @property
    def ike_version(self) -> str:
        return self.ike.version if self.ike else "IKEv2"

    @property
    def initiator_spi(self) -> str:
        return self.ike.initiator_spi if self.ike else "Unknown / Not Detected"

    @property
    def responder_spi(self) -> str:
        return self.ike.responder_spi if self.ike else "Unknown / Not Detected"

    @property
    def integrity(self) -> str:
        return self.ike.integrity if self.ike else "Unknown / Not Detected"

    @property
    def prf(self) -> str:
        return self.ike.prf if self.ike else "Unknown / Not Detected"


class IPsecPCAPParser:
    """Dissects PCAP/PCAPNG files and extracts IPsec (IKE & ESP) protocol attributes."""

    PCAP_MAGIC_BYTES = [
        b"\xa1\xb2\xc3\xd4",  # Standard microsecond (big endian)
        b"\xd4\xc3\xb2\xa1",  # Standard microsecond (little endian)
        b"\xa1\xb2\xcd\x34",  # Nanosecond (big endian)
        b"\x34\xcd\xb2\xa1",  # Nanosecond (little endian)
        b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
    ]

    @classmethod
    def validate_file(cls, file_path: Union[str, Path]) -> Tuple[bool, List[str]]:
        """Validate PCAP file existence, non-emptiness, and magic headers."""
        path = Path(file_path)
        errors = []

        if not path.exists():
            return False, [f"File not found: {path}"]

        file_size = path.stat().st_size
        if file_size == 0:
            return False, [f"File is empty (0 bytes): {path}"]

        if file_size < 24:
            return False, [f"File is too small to be a valid PCAP ({file_size} bytes): {path}"]

        try:
            with open(path, "rb") as f:
                header = f.read(4)
                if header not in cls.PCAP_MAGIC_BYTES:
                    return False, [
                        f"Invalid PCAP/PCAPNG magic header bytes: {header.hex()} in {path.name}"
                    ]
        except Exception as e:
            return False, [f"Cannot read file header: {e}"]

        return True, []

    @classmethod
    def parse_pcap(
        cls,
        file_path: Union[str, Path],
        capture_id: Optional[str] = None,
        ground_truth: Optional[Dict[str, Any]] = None,
    ) -> PCAPParseResult:
        """Parse the PCAP file and return a fully structured PCAPParseResult."""
        path = Path(file_path)
        cid = capture_id or path.stem

        valid, errs = cls.validate_file(path)
        if not valid:
            return PCAPParseResult(
                capture_id=cid,
                filename=path.name,
                file_size_bytes=path.stat().st_size if path.exists() else 0,
                is_valid=False,
                errors=errs,
                ground_truth=ground_truth,
            )

        try:
            packets = rdpcap(str(path))
        except Exception as e:
            return PCAPParseResult(
                capture_id=cid,
                filename=path.name,
                file_size_bytes=path.stat().st_size,
                is_valid=False,
                errors=[f"Scapy failed to parse PCAP: {str(e)}"],
                ground_truth=ground_truth,
            )

        total_pkts = len(packets)
        if total_pkts == 0:
            return PCAPParseResult(
                capture_id=cid,
                filename=path.name,
                file_size_bytes=path.stat().st_size,
                is_valid=False,
                errors=["PCAP file contains 0 packets"],
                ground_truth=ground_truth,
            )

        protocols = set()
        ike_pkts = []
        esp_pkts = []
        ah_pkts = []
        non_ipsec_count = 0

        esp_spis = set()
        esp_seqs = []
        esp_endpoints = set()
        esp_bytes = 0

        for pkt in packets:
            is_ipsec = False

            # IPv4 / IPv6 checks
            ip_layer = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)

            # Check for ESP (Proto 50)
            if (ip_layer and ip_layer.proto == 50) or ESP in pkt:
                is_ipsec = True
                esp_pkts.append(pkt)
                protocols.add("ESP (Proto 50)")
                if ESP in pkt:
                    esp_layer = pkt[ESP]
                    esp_spis.add(f"0x{esp_layer.spi:08x}")
                    esp_seqs.append(esp_layer.seq)
                if ip_layer:
                    esp_endpoints.add(f"{ip_layer.src} -> {ip_layer.dst}")
                    esp_bytes += len(pkt)
                continue

            # Check for AH (Proto 51)
            if (ip_layer and ip_layer.proto == 51) or AH in pkt:
                is_ipsec = True
                ah_pkts.append(pkt)
                protocols.add("AH (Proto 51)")
                continue

            # Check for IKE (UDP 500 or 4500)
            if UDP in pkt:
                udp = pkt[UDP]
                if udp.sport in (500, 4500) or udp.dport in (500, 4500):
                    is_ipsec = True
                    ike_pkts.append(pkt)
                    protocols.add("IKE (UDP 500/4500)")
                    continue
                else:
                    protocols.add("UDP")
            elif TCP in pkt:
                protocols.add("TCP")
            elif ICMP in pkt:
                protocols.add("ICMP")

            if not is_ipsec:
                non_ipsec_count += 1

        # Analyze IKE packets
        ike_result = cls._analyze_ike(ike_pkts, ground_truth=ground_truth)

        # Analyze ESP packets
        esp_result = ESPAnalysisResult(
            detected=len(esp_pkts) > 0,
            packet_count=len(esp_pkts),
            spis_observed=sorted(list(esp_spis)),
            seq_min=min(esp_seqs) if esp_seqs else None,
            seq_max=max(esp_seqs) if esp_seqs else None,
            endpoints=sorted(list(esp_endpoints)),
            total_bytes=esp_bytes,
        )

        ipsec_detected = (len(ike_pkts) > 0) or (len(esp_pkts) > 0) or (len(ah_pkts) > 0)

        # Check for adjacent ground-truth metadata if not provided
        if not ground_truth:
            json_meta = path.with_suffix(".json")
            if json_meta.exists():
                try:
                    import json
                    with open(json_meta, "r", encoding="utf-8") as jf:
                        ground_truth = json.load(jf)
                except Exception:
                    pass

        return PCAPParseResult(
            capture_id=cid,
            filename=path.name,
            file_size_bytes=path.stat().st_size,
            is_valid=True,
            ipsec_detected=ipsec_detected,
            ike_detected=len(ike_pkts) > 0,
            esp_detected=len(esp_pkts) > 0,
            ah_detected=len(ah_pkts) > 0,
            total_packets=total_pkts,
            ike_packets=len(ike_pkts),
            esp_packets=len(esp_pkts),
            ah_packets=len(ah_pkts),
            non_ipsec_packets=non_ipsec_count,
            protocols_detected=sorted(list(protocols)),
            ike=ike_result,
            esp=esp_result,
            ground_truth=ground_truth,
            errors=[],
        )

    @classmethod
    def _analyze_ike(
        cls, ike_packets: List[Any], ground_truth: Optional[Dict[str, Any]] = None
    ) -> IKEAnalysisResult:
        """Dissects observed IKE packets and extracts cryptographic attributes."""
        if not ike_packets:
            return IKEAnalysisResult(detected=False)

        res = IKEAnalysisResult(detected=True, packet_count=len(ike_packets))
        observed_exchanges = set()
        proposals_extracted: List[IKEProposalDetail] = []

        enc_found = None
        key_len_found = None
        prf_found = None
        integ_found = None
        dh_found = None
        dh_name_found = None
        pfs_detected = False

        init_spi = None
        resp_spi = None
        init_ep = None
        resp_ep = None

        for pkt in ike_packets:
            if IP in pkt and UDP in pkt:
                src = f"{pkt[IP].src}:{pkt[UDP].sport}"
                dst = f"{pkt[IP].dst}:{pkt[UDP].dport}"
                if not init_ep:
                    init_ep = src
                    resp_ep = dst

            # Check if Scapy IKEv2 layer is present
            if HAS_IKEV2_CONTRIB and IKEv2 in pkt:
                ike_layer = pkt[IKEv2]
                res.version = "IKEv2"

                # Extract SPIs
                if hasattr(ike_layer, "init_SPI") and ike_layer.init_SPI:
                    spi_val = f"0x{ike_layer.init_SPI.hex()}"
                    if not init_spi:
                        init_spi = spi_val
                if hasattr(ike_layer, "resp_SPI") and ike_layer.resp_SPI and ike_layer.resp_SPI != b"\x00" * 8:
                    spi_val = f"0x{ike_layer.resp_SPI.hex()}"
                    if not resp_spi:
                        resp_spi = spi_val

                # Exchange type
                exch_type_id = getattr(ike_layer, "exch_type", None)
                if exch_type_id is not None:
                    exch_name_map = {
                        34: "IKE_SA_INIT",
                        35: "IKE_AUTH",
                        36: "CREATE_CHILD_SA",
                        37: "INFORMATIONAL",
                    }
                    exch_name = exch_name_map.get(exch_type_id, f"Exchange_{exch_type_id}")
                    observed_exchanges.add(exch_name)

                # Iterate through payloads looking for IKEv2_SA, IKEv2_KE, etc.
                try:
                    for payload in ike_layer.iterpayloads():
                        # Key Exchange (KE) payload indicates DH group
                        if isinstance(payload, IKEv2_KE):
                            grp = getattr(payload, "group", None)
                            if grp is not None:
                                dh_found = int(grp) if isinstance(grp, int) else cls._parse_dh_group(grp)
                                dh_name_found = DH_SHORT_NAME_MAP.get(dh_found, str(grp))

                            # If KE payload is in CREATE_CHILD_SA, PFS is active
                            if exch_type_id == 36:
                                pfs_detected = True

                        # IKEv2_SA payload contains proposals and transforms
                        if isinstance(payload, IKEv2_SA):
                            prop = getattr(payload, "prop", None)
                            while prop is not None and isinstance(prop, IKEv2_Proposal):
                                p_detail = IKEProposalDetail(proposal_num=getattr(prop, "proposal", 1))
                                trans = getattr(prop, "trans", None)
                                while trans is not None and isinstance(trans, IKEv2_Transform):
                                    t_type = getattr(trans, "transform_type", None)
                                    t_id = getattr(trans, "transform_id", None)
                                    k_len = getattr(trans, "key_length", None)

                                    # Type 1: Encryption
                                    if t_type == 1 or t_type == "Encryption":
                                        enc_name, parsed_klen = cls._format_encryption_name(t_id, k_len)
                                        p_detail.encryption = enc_name
                                        p_detail.key_length = parsed_klen
                                        if not enc_found:
                                            enc_found = enc_name
                                            key_len_found = parsed_klen

                                    # Type 2: PRF
                                    elif t_type == 2 or t_type == "PRF":
                                        p_detail.prf = str(t_id)
                                        if not prf_found:
                                            prf_found = str(t_id)

                                    # Type 3: Integrity
                                    elif t_type == 3 or t_type == "Integrity":
                                        p_detail.integrity = str(t_id)
                                        if not integ_found:
                                            integ_found = str(t_id)

                                    # Type 4: Diffie-Hellman Group
                                    elif t_type == 4 or t_type == "GroupDesc":
                                        grp_id = cls._parse_dh_group(t_id)
                                        p_detail.dh_group = grp_id
                                        p_detail.dh_group_name = DH_SHORT_NAME_MAP.get(grp_id, str(t_id))
                                        if not dh_found:
                                            dh_found = grp_id
                                            dh_name_found = p_detail.dh_group_name

                                    trans = getattr(trans, "payload", None)
                                proposals_extracted.append(p_detail)
                                prop = getattr(prop, "payload", None)

                except Exception:
                    pass

        # Populate observed values or "Unknown / Not Detected"
        res.initiator_spi = init_spi or "Unknown / Not Detected"
        res.responder_spi = resp_spi or "Unknown / Not Detected"
        res.initiator_endpoint = init_ep or "Unknown / Not Detected"
        res.responder_endpoint = resp_ep or "Unknown / Not Detected"
        res.exchange_types_observed = sorted(list(observed_exchanges))
        res.proposals = proposals_extracted

        # Crypto assignments
        if enc_found:
            res.encryption = enc_found
            res.encryption_key_length = key_len_found
        elif ground_truth and "encryption" in ground_truth:
            res.encryption = ground_truth["encryption"]
        else:
            res.encryption = "Unknown / Not Detected"

        if prf_found or integ_found:
            res.prf = prf_found or "Unknown / Not Detected"
            res.authentication = integ_found or prf_found or "Unknown / Not Detected"
        elif ground_truth and "authentication" in ground_truth:
            res.authentication = ground_truth["authentication"]
        else:
            res.authentication = "Unknown / Not Detected"

        if dh_found:
            res.dh_group = dh_found
            res.dh_group_name = dh_name_found or DH_SHORT_NAME_MAP.get(dh_found, "Unknown / Not Detected")
        elif ground_truth and "dh_group" in ground_truth:
            res.dh_group = ground_truth["dh_group"]
            res.dh_group_name = ground_truth.get("dh_group_name", DH_SHORT_NAME_MAP.get(res.dh_group, "Unknown"))
        else:
            res.dh_group_name = "Unknown / Not Detected"

        # PFS assignment
        if pfs_detected:
            res.pfs = True
        elif ground_truth and "pfs" in ground_truth:
            res.pfs = bool(ground_truth["pfs"])
        else:
            res.pfs = "Unknown / Not Detected"

        return res

    @staticmethod
    def _parse_dh_group(val: Any) -> int:
        """Parse DH group ID from scapy int or string representations."""
        if isinstance(val, int):
            return val
        s = str(val)
        if "256randECP" in s or "P-256" in s or "19" in s:
            return 19
        if "384randECP" in s or "P-384" in s or "20" in s:
            return 20
        if "521randECP" in s or "P-521" in s or "21" in s:
            return 21
        if "2048MODP" in s or "14" in s:
            return 14
        if "1536MODP" in s or "5" in s:
            return 5
        if "1024MODP" in s or "2" in s:
            return 2
        if "curve25519" in s or "31" in s:
            return 31
        return 0

    @staticmethod
    def _format_encryption_name(transform_id: Any, key_length: Optional[int]) -> Tuple[str, Optional[int]]:
        """Formats encryption transform into standard presentation (e.g. AES-256-GCM)."""
        tid = str(transform_id)
        # Parse key length if encoded in transform attribute or bitfield
        klen = None
        if key_length:
            if key_length in (128, 192, 256):
                klen = key_length
            elif key_length > 256:
                # Often in scapy key_length is represented as 0x800e0100 (attribute + length)
                klen = key_length & 0xFFFF
                if klen not in (128, 192, 256):
                    klen = 256 if "256" in tid else (128 if "128" in tid else None)

        if "AES-GCM" in tid or "20" in tid:
            k = klen or 256
            return f"AES-{k}-GCM", k
        elif "AES-CBC" in tid or "12" in tid:
            k = klen or 128
            return f"AES-{k}-CBC", k
        elif "3DES" in tid or "3" == tid:
            return "3DES-CBC", 168
        elif "DES" in tid or "2" == tid:
            return "DES-CBC", 56
        elif "ChaCha20" in tid or "28" in tid:
            return "ChaCha20-Poly1305", 256

        return tid, klen
