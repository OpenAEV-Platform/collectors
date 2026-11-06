"""Expectation loading: platform expectation data into expectation models."""

from typing import Any, Callable

from collectors_sdk.seam.expectations import ExpectationApiProtocol, ExpectationTypeEnum

__all__ = ["ExpectationLoader"]


class ExpectationLoader:
    """Implements ``ExpectationLoadingPort``."""

    def models_for_source(
        self,
        api: ExpectationApiProtocol,
        source_id: str,
        detection: Callable[..., Any],
        prevention: Callable[..., Any],
        **kwargs: Any,
    ) -> list[Any]:
        # TODO: we should implement a more clever mechanism to obtain
        #   specialised Expectation instances rather than just if/elseing
        #   through this list of possibilities.
        expectations = []
        for expectation_dict in api.expectations_assets_for_source(
            source_id=source_id, **kwargs
        ):
            if (
                expectation_dict["inject_expectation_type"]
                == ExpectationTypeEnum.Detection.value
            ):
                expectations.append(detection(**expectation_dict, api_client=api))
            elif (
                expectation_dict["inject_expectation_type"]
                == ExpectationTypeEnum.Prevention.value
            ):
                expectations.append(prevention(**expectation_dict, api_client=api))
            else:
                expectations.append(prevention(**expectation_dict, api_client=api))
        return expectations
