import pytest
from pydantic import ValidationError

from models.indicator import Indicator, IndicatorType


def test_valid_ip_is_accepted():
    indicator = Indicator(value="8.8.8.8", type=IndicatorType.IP)
    assert indicator.value == "8.8.8.8"


def test_invalid_ip_is_rejected():
    with pytest.raises(ValidationError):
        Indicator(value="not-an-ip", type=IndicatorType.IP)


def test_ip_value_is_stripped():
    indicator = Indicator(value="  8.8.8.8  ", type=IndicatorType.IP)
    assert indicator.value == "8.8.8.8"
