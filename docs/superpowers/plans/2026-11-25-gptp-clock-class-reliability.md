# gPTP clockClass Reliability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show M22 Grandmaster clockClass and derive a fresh, customer-defined gPTP time reliability state in Slave mode.

**Architecture:** Extend the Slave snapshot with full Announce metadata and a `TimeReliability` enum computed from clockClass and Announce age. The existing GUI consumes that immutable snapshot, displays a colored badge and compact Announce details, and deduplicates transition logs.

**Tech Stack:** Python, existing Scapy/PyQt5 GUI, pytest offscreen

---

### Task 1: Add Reliability State to Slave Analyzer

**Files:**
- Modify: `src/gptp_monitor/slave.py`
- Modify: `tests/test_slave.py`

- [ ] **Step 1: Write failing reliability tests**

```python
from gptp_monitor.slave import TimeReliability


def _announce_with_class(clock_class: int, sequence_id: int = 1) -> bytes:
    return _builder().announce(
        sequence_id=sequence_id,
        timestamp=PtpTimestamp(1, 0),
        clock_class=clock_class,
    )


def test_clock_class_maps_to_reliability_and_updates_in_sequence():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    for index, (clock_class, expected) in enumerate((
        (248, TimeReliability.WAITING_GNSS),
        (6, TimeReliability.GNSS_LOCKED),
        (13, TimeReliability.DEGRADED),
        (6, TimeReliability.GNSS_LOCKED),
        (52, TimeReliability.TRANSITIONING),
        (77, TimeReliability.UNKNOWN),
    )):
        analyzer.handle_frame(
            _announce_with_class(clock_class, sequence_id=index),
            received_ns=index,
            monotonic_ns=index,
        )
        snapshot = analyzer.snapshot(monotonic_ns=index)
        assert snapshot.grandmaster_clock_class == clock_class
        assert snapshot.announce_sequence_id == index
        assert snapshot.reliability == expected


def test_class_6_becomes_stale_after_three_seconds_without_announce():
    analyzer = SlaveAnalyzer(SlaveConfig(), send_frame=lambda _: None)
    analyzer.handle_frame(
        _announce_with_class(6),
        received_ns=1,
        monotonic_ns=1_000_000_000,
    )
    assert analyzer.snapshot(
        monotonic_ns=3_500_000_000
    ).reliability == TimeReliability.GNSS_LOCKED
    stale = analyzer.snapshot(monotonic_ns=4_100_000_000)
    assert stale.reliability == TimeReliability.STALE
    assert stale.grandmaster_clock_class == 6
    assert stale.announce_age_ns == 3_100_000_000


def test_no_announce_never_reports_locked():
    snapshot = SlaveAnalyzer(
        SlaveConfig(),
        send_frame=lambda _: None,
    ).snapshot(monotonic_ns=1)
    assert snapshot.reliability == TimeReliability.UNKNOWN
    assert snapshot.grandmaster_clock_class is None
```

- [ ] **Step 2: Run tests and verify failure**

Run: `python -m pytest tests/test_slave.py -q`
Expected: FAIL because `TimeReliability` and new snapshot fields do not exist.

- [ ] **Step 3: Implement snapshot fields and mapping**

Add:

```python
class TimeReliability(str, Enum):
    UNKNOWN = "UNKNOWN"
    WAITING_GNSS = "WAITING_GNSS"
    GNSS_LOCKED = "GNSS_LOCKED"
    DEGRADED = "DEGRADED"
    TRANSITIONING = "TRANSITIONING"
    STALE = "STALE"


CLOCK_CLASS_RELIABILITY = {
    6: TimeReliability.GNSS_LOCKED,
    13: TimeReliability.DEGRADED,
    52: TimeReliability.TRANSITIONING,
    248: TimeReliability.WAITING_GNSS,
}
```

Add to `SlaveConfig`:

```python
reliability_stale_ns: int = 3_000_000_000
```

Add to `SlaveSnapshot`:

```python
announce_sequence_id: int | None = None
grandmaster_clock_accuracy: int | None = None
grandmaster_clock_variance: int | None = None
grandmaster_steps_removed: int | None = None
grandmaster_time_source: int | None = None
announce_age_ns: int | None = None
reliability: TimeReliability = TimeReliability.UNKNOWN
```

Keep the existing `grandmaster_clock_class`,
`grandmaster_priority1` and `grandmaster_priority2` fields; do not duplicate
them.

In `_handle_announce`, store sequence, accuracy, variance, stepsRemoved and
timeSource from `AnnounceData` while preserving the current locked-source rule.

In `_snapshot_with_timeout`, compute:

```python
age = None if self._last_announce_mono is None else now - self._last_announce_mono
if self._snapshot.grandmaster_clock_class is None:
    reliability = TimeReliability.UNKNOWN
elif age > self.config.reliability_stale_ns:
    reliability = TimeReliability.STALE
else:
    reliability = CLOCK_CLASS_RELIABILITY.get(
        self._snapshot.grandmaster_clock_class,
        TimeReliability.UNKNOWN,
    )
```

Return a snapshot updated with `announce_age_ns` and `reliability`.
`_clear_lock` resets all new fields.

- [ ] **Step 4: Run analyzer tests**

Run: `python -m pytest tests/test_slave.py -q`
Expected: PASS.

- [ ] **Step 5: Commit Task 1**

```bash
git add src/gptp_monitor/slave.py tests/test_slave.py
git commit -m "feat: derive gPTP time reliability from clockClass"
```

### Task 2: Display Reliability in Slave GUI

**Files:**
- Modify: `src/gptp_monitor/gui/window.py`
- Modify: `tests/test_gui.py`
- Modify: `docs/METRICS.md`
- Modify: `docs/USER_GUIDE.md`

- [ ] **Step 1: Add failing GUI tests**

```python
def test_slave_reliability_badge_and_announce_fields():
    from gptp_monitor.slave import SlaveState, TimeReliability

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    window = MainWindow(interface_names=["Ethernet 4"], controller=object())
    window.apply_snapshot({
        "role": "slave",
        "state": SlaveState.SYNCING,
        "grandmaster_identity": bytes.fromhex("8e616ffffe952e36"),
        "grandmaster_clock_class": 6,
        "grandmaster_clock_accuracy": 0xFE,
        "grandmaster_clock_variance": 0xFFFF,
        "grandmaster_steps_removed": 0,
        "grandmaster_time_source": 0xA0,
        "announce_sequence_id": 29,
        "announce_age_ns": 120_000_000,
        "reliability": TimeReliability.GNSS_LOCKED,
        "errors": 0,
        "recent_syncs": (),
    })
    assert window.reliability_label.text() == "GNSS_LOCKED"
    assert "class=6" in window.gm_label.text()
    assert "seq=29" in window.gm_label.text()
    assert "GNSS_LOCKED" in window.log.toPlainText()
    window.close()
    app.processEvents()
```

Add parametrized tests for 248,13,52,unknown and stale colors/text.

- [ ] **Step 2: Run test and verify failure**

Run: `python -m pytest tests/test_gui.py::test_slave_reliability_badge_and_announce_fields -q`
Expected: FAIL because `reliability_label` does not exist.

- [ ] **Step 3: Add reliability widget and transition log**

Create `self.reliability_label` beside `self.state_label`, bold and compact.

In `apply_snapshot` for Slave:

```python
reliability = snapshot.get("reliability", TimeReliability.UNKNOWN)
reliability_text = getattr(reliability, "value", str(reliability))
self.reliability_label.setText(reliability_text)
```

Apply colors:

- GNSS_LOCKED: green.
- WAITING_GNSS and TRANSITIONING: amber.
- DEGRADED and STALE: red.
- UNKNOWN: gray.

Update GM text with compact:

```text
GM: <identity> class=<class> seq=<seq> age=<ms> steps=<steps>
```

Use a full multi-line Tooltip for clockAccuracy, variance, timeSource and full
identity.

Maintain `_last_reliability` and `_last_reliability_class`. Append one log
message only when reliability or class changes:

```text
clockClass 248 -> 6, WAITING_GNSS -> GNSS_LOCKED
```

Clear both values on session start, stop and role switch.

- [ ] **Step 4: Update metric documentation**

Document the class mapping, 3-second stale rule, state colors, and the fact
that class 6 means GNSS traceability rather than measured offset precision.

- [ ] **Step 5: Run GUI tests**

Run: `python -m pytest tests/test_gui.py tests/test_slave.py -q`
Expected: PASS.

- [ ] **Step 6: Commit Task 2**

```bash
git add src/gptp_monitor/gui/window.py tests/test_gui.py docs/METRICS.md docs/USER_GUIDE.md
git commit -m "feat: show gPTP clockClass reliability status"
```

### Task 3: Live Verification

**Files:**
- Modify: `docs/RELEASE_VERIFICATION.md`

- [ ] **Step 1: Run full automated verification**

Run:

```powershell
python -m pytest tests -q
python -m gptp_monitor.gui --offscreen --smoke-ui
```

Expected: all tests pass and smoke exits `0`.

- [ ] **Step 2: Verify M22 transitions**

Capture Announce before and after GNSS synchronization and verify:

- initial class 248 and `WAITING_GNSS`.
- synchronized class 6 and `GNSS_LOCKED`.
- antenna removal class 13 and `DEGRADED`.
- antenna recovery to class 6 and `GNSS_LOCKED`.
- Announce stops for over 3 seconds and state becomes `STALE`.

Record the Announce sequence IDs and observed timestamps. Do not fabricate
transitions that were not observed.

- [ ] **Step 3: Update verification documentation**

Add actual evidence and commit:

```bash
git add docs/RELEASE_VERIFICATION.md
git commit -m "docs: verify M22 gPTP clockClass reliability"
```
