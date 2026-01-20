from models import Alert


def alerts_filtered_by_implant_id(alerts: list[Alert], implant_id: str) -> list[Alert]:
    """
    Filters a list of alerts by a specific implant ID.

    :param alerts: List of Alert objects to filter.
    :param implant_id: The implant ID to filter alerts by.
    :return: A list of Alert objects that match the specified implant ID.
    """

    return list(
        filter(
            lambda alert: implant_id in (alert.actor_process_command_line or ""), alerts
        )
    )
