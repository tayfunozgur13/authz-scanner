from apps.hardened_api.models import Invoice as HardenedInvoice
from apps.hardened_api.models import Order as HardenedOrder
from apps.hardened_api.models import OrderItem as HardenedOrderItem
from apps.hardened_api.models import Organization as HardenedOrganization
from apps.hardened_api.models import SupportTicket as HardenedSupportTicket
from apps.hardened_api.models import User as HardenedUser
from apps.vulnerable_api.models import Invoice as VulnerableInvoice
from apps.vulnerable_api.models import Order as VulnerableOrder
from apps.vulnerable_api.models import OrderItem as VulnerableOrderItem
from apps.vulnerable_api.models import Organization as VulnerableOrganization
from apps.vulnerable_api.models import SupportTicket as VulnerableSupportTicket
from apps.vulnerable_api.models import User as VulnerableUser


def test_vulnerable_api_models_have_expected_tables() -> None:
    assert VulnerableUser.__tablename__ == "users"
    assert VulnerableOrganization.__tablename__ == "organizations"
    assert VulnerableOrder.__tablename__ == "orders"
    assert VulnerableOrderItem.__tablename__ == "order_items"
    assert VulnerableInvoice.__tablename__ == "invoices"
    assert VulnerableSupportTicket.__tablename__ == "support_tickets"


def test_hardened_api_models_have_expected_tables() -> None:
    assert HardenedUser.__tablename__ == "users"
    assert HardenedOrganization.__tablename__ == "organizations"
    assert HardenedOrder.__tablename__ == "orders"
    assert HardenedOrderItem.__tablename__ == "order_items"
    assert HardenedInvoice.__tablename__ == "invoices"
    assert HardenedSupportTicket.__tablename__ == "support_tickets"
