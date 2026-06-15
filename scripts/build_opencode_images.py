#!/usr/bin/env python3
"""
OpenCode Image Builder

Builds OpenCode-enabled images for multiple base OS distributions.
Supports Ubuntu 24.04, Ubuntu 22.04, and Debian 12.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional


# Supported base images and their corresponding tags
BASE_IMAGES = {
    "ubuntu24": "ubuntu:24.04",
    "ubuntu22": "ubuntu:22.04",
    "debian12": "debian:12"
}

# Output image tags
IMAGE_TAGS = {
    "ubuntu24": "stratocyberlab/scl-opencode-ubuntu24:0.1",
    "ubuntu22": "stratocyberlab/scl-opencode-ubuntu22:0.1",
    "debian12": "stratocyberlab/scl-opencode-debian12:0.1"
}


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Build OpenCode Docker images for multiple base OS distributions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Build all images
  %(prog)s --all

  # Build specific images
  %(prog)s --base ubuntu24 ubuntu22

  # Build with custom Dockerfile
  %(prog)s --all --dockerfile /path/to/Dockerfile.opencode

  # Build with custom build args
  %(prog)s --base ubuntu24 --build-arg OPENCODE_VERSION=1.2.3
        """
    )

    parser.add_argument(
        "--base",
        nargs="+",
        choices=list(BASE_IMAGES.keys()) + list(BASE_IMAGES.values()),
        help="Base image(s) to build (e.g., ubuntu24, ubuntu:24.04)"
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Build all supported base images"
    )

    parser.add_argument(
        "--dockerfile",
        type=Path,
        default=Path(__file__).parent.parent / "images" / "Dockerfile.opencode",
        help="Path to Dockerfile.opencode (default: ../images/Dockerfile.opencode)"
    )

    parser.add_argument(
        "--build-arg",
        action="append",
        dest="build_args",
        metavar="KEY=VALUE",
        help="Build arguments to pass to docker build (can be used multiple times)"
    )

    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable Docker build cache"
    )

    parser.add_argument(
        "--push",
        action="store_true",
        help="Push images to registry after building"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing"
    )

    parser.add_argument(
        "--verify",
        action="store_true",
        default=True,
        help="Verify builds succeeded (default: True)"
    )

    parser.add_argument(
        "--no-verify",
        action="store_false",
        dest="verify",
        help="Skip build verification"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    return parser.parse_args()


def normalize_base_image(base: str) -> str:
    """Normalize base image name to key format."""
    if ":" in base:
        for key, value in BASE_IMAGES.items():
            if value == base:
                return key
    return base


def get_build_targets(args: argparse.Namespace) -> List[str]:
    """Determine which base images to build."""
    if args.all:
        return list(BASE_IMAGES.keys())
    elif args.base:
        return [normalize_base_image(b) for b in args.base]
    else:
        print("Error: Must specify --base or --all", file=sys.stderr)
        sys.exit(1)


def check_dockerfile(dockerfile_path: Path) -> None:
    """Check if Dockerfile exists."""
    if not dockerfile_path.exists():
        print(f"Error: Dockerfile not found at {dockerfile_path}", file=sys.stderr)
        sys.exit(1)


def check_docker() -> None:
    """Check if Docker is available."""
    try:
        subprocess.run(
            ["docker", "--version"],
            check=True,
            capture_output=True,
            text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: Docker is not available or not running", file=sys.stderr)
        sys.exit(1)


def build_image(
    base_key: str,
    dockerfile: Path,
    build_args: Optional[List[str]] = None,
    no_cache: bool = False,
    dry_run: bool = False,
    verbose: bool = False
) -> bool:
    """Build a single OpenCode image."""
    base_image = BASE_IMAGES[base_key]
    output_tag = IMAGE_TAGS[base_key]

    # Build docker command
    cmd = [
        "docker", "build",
        "--build-arg", f"BASE_IMAGE={base_image}",
        "--tag", output_tag,
        "--file", str(dockerfile),
        "--platform", "linux/amd64"
    ]

    # Add user build args
    if build_args:
        for arg in build_args:
            cmd.extend(["--build-arg", arg])

    # Add no-cache flag
    if no_cache:
        cmd.append("--no-cache")

    # Build context is the directory containing the Dockerfile
    build_context = dockerfile.parent
    cmd.append(str(build_context))

    if verbose or dry_run:
        print(f"\nBuilding: {base_key} -> {output_tag}")
        print(f"Base image: {base_image}")
        print(f"Command: {' '.join(cmd)}")

    if dry_run:
        return True

    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=not verbose,
            text=True
        )
        if verbose and result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"\nError building {base_key}: {e}", file=sys.stderr)
        if not verbose and e.stderr:
            print(e.stderr, file=sys.stderr)
        return False


def verify_image(image_tag: str, dry_run: bool = False, verbose: bool = False) -> bool:
    """Verify that an image was built successfully."""
    cmd = ["docker", "inspect", "--type=image", image_tag]

    if verbose or dry_run:
        print(f"Verifying: {image_tag}")
        print(f"Command: {' '.join(cmd)}")

    if dry_run:
        return True

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        if verbose:
            print(f"✓ Image {image_tag} verified successfully")
        return True
    except subprocess.CalledProcessError:
        print(f"✗ Image {image_tag} verification failed", file=sys.stderr)
        return False


def push_image(image_tag: str, dry_run: bool = False, verbose: bool = False) -> bool:
    """Push an image to registry."""
    cmd = ["docker", "push", image_tag]

    if verbose or dry_run:
        print(f"Pushing: {image_tag}")
        print(f"Command: {' '.join(cmd)}")

    if dry_run:
        return True

    try:
        subprocess.run(cmd, check=True, capture_output=not verbose, text=True)
        if verbose:
            print(f"✓ Image {image_tag} pushed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to push {image_tag}: {e}", file=sys.stderr)
        return False


def main() -> int:
    """Main entry point."""
    args = parse_arguments()

    # Validate inputs
    check_dockerfile(args.dockerfile)
    check_docker()

    # Get build targets
    targets = get_build_targets(args)

    # Prepare build args
    build_args_list = args.build_args or []

    # Build summary
    print("\n" + "=" * 60)
    print("OpenCode Image Builder")
    print("=" * 60)
    print(f"Dockerfile: {args.dockerfile}")
    print(f"Targets: {', '.join(targets)}")
    print(f"No cache: {args.no_cache}")
    print(f"Verify builds: {args.verify}")
    print(f"Push images: {args.push}")
    if args.dry_run:
        print("DRY RUN MODE - No actual builds will be performed")
    print("=" * 60 + "\n")

    # Track results
    results: Dict[str, Dict[str, bool]] = {}

    for target in targets:
        if target not in BASE_IMAGES:
            print(f"Warning: Unknown target '{target}', skipping", file=sys.stderr)
            continue

        print(f"\n--- Building {target} ---")

        # Build image
        build_success = build_image(
            target,
            args.dockerfile,
            build_args_list,
            args.no_cache,
            args.dry_run,
            args.verbose
        )

        results[target] = {"build": build_success}

        # Verify if requested
        if args.verify and build_success and not args.dry_run:
            verify_success = verify_image(
                IMAGE_TAGS[target],
                args.dry_run,
                args.verbose
            )
            results[target]["verify"] = verify_success

        # Push if requested
        if args.push and build_success and not args.dry_run:
            if not args.verify or results[target].get("verify", True):
                push_success = push_image(
                    IMAGE_TAGS[target],
                    args.dry_run,
                    args.verbose
                )
                results[target]["push"] = push_success

    # Print summary
    print("\n" + "=" * 60)
    print("Build Summary")
    print("=" * 60)

    all_success = True
    for target, result in results.items():
        status = "✓ SUCCESS" if result.get("build", False) else "✗ FAILED"
        print(f"{target:12} | {IMAGE_TAGS[target]:40} | {status}")
        if not result.get("build", False):
            all_success = False
        if args.verify and "verify" in result:
            print(f"{'':12} | {'':40} | Verify: {'✓' if result['verify'] else '✗'}")
        if args.push and "push" in result:
            print(f"{'':12} | {'':40} | Push: {'✓' if result['push'] else '✗'}")

    print("=" * 60)

    if all_success:
        print("\n✓ All images built successfully!")
        return 0
    else:
        print("\n✗ Some builds failed. Check output above for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
