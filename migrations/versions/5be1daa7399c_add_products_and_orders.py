"""add products and orders

Revision ID: 5be1daa7399c
Revises: 7a082b06b323
Create Date: 2016-12-22 11:36:26.221069

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '5be1daa7399c'
down_revision = '7a082b06b323'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('orders',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('createdAt', mysql.DATETIME(), nullable=False),
    sa.Column('updatedAt', mysql.DATETIME(), nullable=False),
    sa.Column('total', sa.Numeric(precision=8, scale=2, asdecimal=False), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('product',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('createdAt', mysql.DATETIME(), nullable=False),
    sa.Column('updatedAt', mysql.DATETIME(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=True),
    sa.Column('price', sa.Numeric(precision=8, scale=2, asdecimal=False), nullable=True),
    sa.Column('purchase_price', sa.Numeric(precision=8, scale=2, asdecimal=False), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('product')
    op.drop_table('orders')
    # ### end Alembic commands ###
