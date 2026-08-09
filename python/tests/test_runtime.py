"""The seam between the crate's runtime and asyncio's.

Nothing here touches the network, so these run wherever Python does; what
they check is that a blocking call really does leave the event loop alone,
and that a coroutine handed back from one of the library's own threads really
does run on the caller's loop.
"""

import asyncio
import threading
import time

import pytest

import soyokaze
from soyokaze.runtime import Runtime, Threads, offload, resolved

async def test_an_offloaded_call_is_made_on_another_thread():
    where = await offload(threading.get_ident)
    assert where != threading.get_ident(), "the call must not be made on the event loop's thread"

async def test_an_offloaded_call_hands_its_result_and_its_failure_back():
    assert await offload(divmod, 7, 2) == (3, 1)

    with pytest.raises(ZeroDivisionError):
        await offload(divmod, 7, 0)

async def test_the_loop_keeps_running_while_an_offloaded_call_waits():
    ticks = 0

    async def tick():
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.01)

    ticking = asyncio.create_task(tick())
    began = time.monotonic()
    await offload(time.sleep, 0.2)
    ticking.cancel()

    assert time.monotonic() - began >= 0.2, "the call must actually have waited"
    assert ticks > 1, "the loop must have run other work while it waited"

async def test_offloaded_calls_wait_alongside_each_other():
    began = time.monotonic()
    await asyncio.gather(*[offload(time.sleep, 0.2) for _ in range(4)])

    assert time.monotonic() - began < 0.6, "four waits of 0.2s must not add up to 0.8s"

async def test_a_plain_value_is_resolved_without_the_loop_hearing_of_it():
    loop = asyncio.get_running_loop()
    assert await offload(resolved, "answer", loop) == "answer"

async def test_a_coroutine_is_resolved_on_the_loop_it_was_given():
    loop = asyncio.get_running_loop()

    async def answer():
        await asyncio.sleep(0)
        return threading.get_ident()

    # Called from a worker thread, exactly as a handler is called from one of
    # the library's own: the coroutine must run on the loop all the same.
    where = await offload(resolved, answer(), loop)
    assert where == threading.get_ident(), "a coroutine handler must run on the caller's loop"

async def test_what_a_resolved_coroutine_raises_reaches_the_caller():
    loop = asyncio.get_running_loop()

    async def broken():
        raise ValueError("deliberate")

    with pytest.raises(ValueError, match="deliberate"):
        await offload(resolved, broken(), loop)

def test_the_shared_pool_is_built_once_and_refuses_to_be_rebuilt():
    assert Threads.default() is Threads.default()

    with pytest.raises(soyokaze.errors.RuntimeError):
        Threads.configure(4)

def test_the_shared_runtime_is_built_once():
    assert Runtime.default() is Runtime.default()
    assert Runtime.default().handle
