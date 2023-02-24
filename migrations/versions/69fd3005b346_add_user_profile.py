"""add user profile

Revision ID: 69fd3005b346
Revises: 3464a7bb0906
Create Date: 2023-02-14 19:48:24.628699

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '69fd3005b346'
down_revision = '3464a7bb0906'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('name', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('location', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('about_me', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('member_since', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('last_seen', sa.DateTime(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('last_seen')
        batch_op.drop_column('member_since')
        batch_op.drop_column('about_me')
        batch_op.drop_column('location')
        batch_op.drop_column('name')

    # ### end Alembic commands ###