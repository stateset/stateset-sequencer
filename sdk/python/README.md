# StateSet Sequencer Python SDK

Typed synchronous and asynchronous clients for signed, idempotent VES agent
actions. Requires Python 3.10 or newer.

```bash
pip install stateset-sequencer-sdk
```

```python
import os
import uuid
from stateset_sequencer import SequencerClient, load_private_key

with SequencerClient(
    base_url=os.environ["STATESET_SEQUENCER_URL"],
    tenant_id=os.environ["STATESET_TENANT_ID"],
    store_id=os.environ["STATESET_STORE_ID"],
    agent_id=os.environ["STATESET_AGENT_ID"],
    api_key=os.environ["STATESET_API_KEY"],
    private_key=load_private_key(),
) as sequencer:
    result = sequencer.record_action(
        entity_type="order",
        entity_id="ORD-123",
        event_type="order.confirmed",
        command_id=str(uuid.uuid4()),
        base_version=1,
        payload={"approved_by": "fulfillment-agent"},
    )
```

Use `AsyncSequencerClient` in async agent runtimes; it exposes the same methods
as coroutines. Keep the private key and API credential in the tool host, never
in model context. Reuse `command_id` for every retry of one logical action.

`SEQUENCER_TOOLS` contains OpenAI-compatible function definitions.
`create_tool_executor()` and `create_async_tool_executor()` bind them to a
client and default to read-only; writes require an explicit
`allowed_event_types` set.
