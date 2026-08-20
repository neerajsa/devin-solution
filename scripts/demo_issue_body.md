Ran the full unit test suite (`pytest tests/unit_tests/`) and noticed 7 failures clustered around date/time filtering - most in `jinja_context_test.py::test_get_time_filter`, one in `date_parser_tests.py::test_previous_calendar_quarter`. The latter has a clear assertion failure:

```
tests/unit_tests/utils/date_parser_tests.py:357: AssertionError
E           assert (datetime.dat... 10, 1, 0, 0)) == (FakeDatetime..., 1, 1, 0, 0))
E             At index 0 diff: datetime.datetime(2023, 7, 1, 0, 0) != FakeDatetime(2023, 10, 1, 0, 0)
E             Full diff:
E             - (FakeDatetime(2023, 10, 1, 0, 0), FakeDatetime(2024, 1, 1, 0, 0))
E             + (datetime.datetime(2023, 7, 1, 0, 0), datetime.datetime(2023, 10, 1, 0, 0))
```

Not sure yet why this is failing - will have Devin look into the root cause and fix it.
