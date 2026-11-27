"""Shared test helpers. This file is not a unittest discovery module."""

from __future__ import annotations


def add_matrix_tests(cls, cases, prefix, runner):
    """Attach one independently selectable test method per matrix case."""

    for index, case in enumerate(cases):
        if not isinstance(case, tuple):
            case = (case,)

        def make_test(bound_case):
            def test_method(self):
                runner(self, *bound_case)
            return test_method

        name = "test_%s_%03d" % (prefix, index)
        setattr(cls, name, make_test(case))
    return cls
