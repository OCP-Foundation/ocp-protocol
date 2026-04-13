"""OCP Reference Node — serves transport, registry, and custodian components."""

__version__ = "1.0.0"


═══ FILE: node/src/ocp_node/__main__.py ═══

"""Entry point: python -m ocp_node"""

import argparse
import asyncio
import sys

import structlog
import yaml

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ],
)

log = structlog.get_logger()


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


async def run_node(cfg: dict) -> None:
    from ocp_node.transport_server import TransportServer
    server = TransportServer(cfg)
    await server.start()


async def run_registry(cfg: dict) -> None:
    from ocp_node.registry_server import RegistryServer
    server = RegistryServer(cfg)
    await server.start()


async def run_custodian(cfg: dict) -> None:
    from ocp_node.custodian_server import CustodianServer
    server = CustodianServer(cfg)
    await server.start()


async def run_all(cfg: dict) -> None:
    """Run all components in a single process (development mode)."""
    from ocp_node.transport_server import TransportServer
    from ocp_node.registry_server import RegistryServer
    from ocp_node.custodian_server import CustodianServer

    transport = TransportServer(cfg)
    registry = RegistryServer(cfg)
    custodian = CustodianServer(cfg)

    await asyncio.gather(
        transport.start(),
        registry.start(),
        custodian.start(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="OCP Reference Node")
    parser.add_argument(
        "--component",
        choices=["node", "registry", "custodian", "all"],
        default="all",
        help="Component to run (default: all)",
    )
    parser.add_argument(
        "--config",
        default="/app/config.yml",
        help="Path to config.yml",
    )
    args = parser.parse_args()

    import os
    config_path = os.environ.get("OCP_CONFIG", args.config)

    try:
        cfg = load_config(config_path)
    except FileNotFoundError:
        log.error("Config not found", path=config_path)
        sys.exit(1)

    log.info(
        "Starting OCP node",
        component=args.component,
        network=cfg.get("node", {}).get("network", "mainnet"),
        version=__version__,
    )

    runners = {
        "node": run_node,
        "registry": run_registry,
        "custodian": run_custodian,
        "all": run_all,
    }

    try:
        asyncio.run(runners[args.component](cfg))
    except KeyboardInterrupt:
        log.info("Shutting down")


if __name__ == "__main__":
    main()

from ocp_node import __version__  # noqa: E402
