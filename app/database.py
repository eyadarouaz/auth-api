from sqlmodel import Session, create_engine

from app.config import settings

# Create the database engine
engine = create_engine(settings.DATABASE_URI, echo=True)


# Function to get the database session
def get_db():
    with Session(engine) as session:
        yield session
