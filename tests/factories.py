import factory
from faker import Faker
from passlib.context import CryptContext

from app.models import Role, Status, User

fake = Faker()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserFactory(factory.Factory):
    class Meta:
        model = User

    username = factory.LazyAttribute(lambda _: fake.user_name())
    email = factory.LazyAttribute(lambda _: fake.email())
    full_name = factory.LazyAttribute(lambda _: fake.name())
    validation_code = factory.LazyAttribute(lambda _: fake.pystr())
    status = factory.LazyAttribute(
        lambda _: fake.random_element([Status.pending, Status.active])
    )
    role = factory.LazyAttribute(lambda _: fake.random_element([Role.admin, Role.user]))
    hashed_password = factory.LazyAttribute(
        lambda _: pwd_context.hash("defaultpassword")
    )
