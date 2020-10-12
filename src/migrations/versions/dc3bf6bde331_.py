"""empty message

Revision ID: dc3bf6bde331
Revises: 
Create Date: 2020-10-12 20:43:16.430736

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dc3bf6bde331'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('abusefilter',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('wiki', sa.String(length=255), nullable=True),
    sa.Column('filter_id', sa.Integer(), nullable=True),
    sa.Column('description', sa.String(length=255), nullable=True),
    sa.Column('enabled', sa.Boolean(), nullable=True),
    sa.Column('pattern', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('abusefilter')
    # ### end Alembic commands ###