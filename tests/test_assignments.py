import asyncio
import sys
import os
from pathlib import Path

# Add backend dir to python path (use relative path for portability)
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir.parent))

from backend.services.agent_lifecycle import get_agent_assignments_async

async def main():
    print("Testing get_agent_assignments_async...")
    try:
        assignments = await get_agent_assignments_async()
        print(f"Got {len(assignments)} assignments:")
        for a in assignments:
            print(a.dict())
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
