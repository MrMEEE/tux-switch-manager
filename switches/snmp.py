import asyncio
import os

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData, ContextData, ObjectIdentity, ObjectType,
    SnmpEngine, UdpTransportTarget, Udp6TransportTarget, bulk_walk_cmd,
)

from .models import credential_validator

COLUMNS = {
    "name": "1.3.6.1.2.1.31.1.1.1.1",
    "admin_status": "1.3.6.1.2.1.2.2.1.7",
    "oper_status": "1.3.6.1.2.1.2.2.1.8",
    "in_octets": "1.3.6.1.2.1.31.1.1.1.6",
    "out_octets": "1.3.6.1.2.1.31.1.1.1.10",
}


async def collect_interfaces(device):
    credential_validator(device.snmp_credential_env)
    community = os.environ.get(device.snmp_credential_env)
    if not community:
        raise ValueError("SNMP credential reference is unavailable.")
    engine = SnmpEngine()
    interfaces = {}
    try:
        transport = Udp6TransportTarget if ":" in device.address else UdpTransportTarget
        target = await transport.create((device.address, device.snmp_port), timeout=2, retries=0)
        for column, oid in COLUMNS.items():
            async for error, status, index, bindings in bulk_walk_cmd(
                engine, CommunityData(community, mpModel=1), target, ContextData(),
                0, 25, ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False, maxRows=512,
            ):
                if error or status:
                    raise ValueError("SNMP interface polling failed.")
                for name, value in bindings:
                    numeric = name.prettyPrint()
                    if not numeric.startswith(oid + "."):
                        continue
                    interface_id = numeric[len(oid) + 1:]
                    if not interface_id.isdigit():
                        continue
                    interfaces.setdefault(interface_id, {})[column] = (
                        value.prettyPrint() if column == "name" else int(value)
                    )
        return interfaces
    finally:
        engine.close_dispatcher()


def poll_interfaces(device):
    async def bounded():
        return await asyncio.wait_for(collect_interfaces(device), timeout=30)

    return asyncio.run(bounded())
