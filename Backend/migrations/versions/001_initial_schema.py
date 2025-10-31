"""
Initial database schema
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=50), nullable=False),
        sa.Column('email', sa.String(length=100), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=100), nullable=True),
        sa.Column('role', sa.String(length=20), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('is_superuser', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('preferences', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)

    op.create_table('attack_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('event_id', sa.String(length=50), nullable=True),
        sa.Column('honeypot_type', sa.String(length=20), nullable=False),
        sa.Column('source_ip', sa.String(length=45), nullable=False),
        sa.Column('source_port', sa.Integer(), nullable=True),
        sa.Column('destination_port', sa.Integer(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('payload', sa.Text(), nullable=True),
        sa.Column('method', sa.String(length=10), nullable=True),
        sa.Column('url', sa.Text(), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('country', sa.String(length=2), nullable=True),
        sa.Column('city', sa.String(length=100), nullable=True),
        sa.Column('latitude', sa.Float(), nullable=True),
        sa.Column('longitude', sa.Float(), nullable=True),
        sa.Column('asn', sa.String(length=50), nullable=True),
        sa.Column('organization', sa.String(length=255), nullable=True),
        sa.Column('threat_level', sa.String(length=20), nullable=True),
        sa.Column('ml_confidence', sa.Float(), nullable=True),
        sa.Column('is_malicious', sa.Boolean(), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('raw_data', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_attack_events_event_id'), 'attack_events', ['event_id'], unique=True)
    op.create_index(op.f('ix_attack_events_id'), 'attack_events', ['id'], unique=False)
    op.create_index(op.f('ix_attack_events_source_ip'), 'attack_events', ['source_ip'], unique=False)
    op.create_index(op.f('ix_attack_events_timestamp'), 'attack_events', ['timestamp'], unique=False)

    op.create_table('attacker_profiles',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('attack_count', sa.Integer(), nullable=True),
        sa.Column('country', sa.String(length=2), nullable=True),
        sa.Column('asn', sa.String(length=50), nullable=True),
        sa.Column('organization', sa.String(length=255), nullable=True),
        sa.Column('threat_score', sa.Integer(), nullable=True),
        sa.Column('is_blocked', sa.Boolean(), nullable=True),
        sa.Column('behavior_patterns', sa.JSON(), nullable=True),
        sa.Column('attack_methods', sa.JSON(), nullable=True),
        sa.Column('last_attack_type', sa.String(length=50), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_attacker_profiles_id'), 'attacker_profiles', ['id'], unique=False)
    op.create_index(op.f('ix_attacker_profiles_ip_address'), 'attacker_profiles', ['ip_address'], unique=True)

    op.create_table('ml_predictions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('event_id', sa.String(length=50), nullable=True),
        sa.Column('model_name', sa.String(length=50), nullable=False),
        sa.Column('prediction', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('features', sa.JSON(), nullable=True),
        sa.Column('shap_values', sa.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('model_version', sa.String(length=20), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ml_predictions_event_id'), 'ml_predictions', ['event_id'], unique=False)
    op.create_index(op.f('ix_ml_predictions_id'), 'ml_predictions', ['id'], unique=False)

    op.create_table('response_actions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('action_id', sa.String(length=50), nullable=True),
        sa.Column('event_id', sa.String(length=50), nullable=True),
        sa.Column('attacker_ip', sa.String(length=45), nullable=False),
        sa.Column('action_type', sa.String(length=20), nullable=False),
        sa.Column('action_details', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('created_by', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ttl', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_response_actions_action_id'), 'response_actions', ['action_id'], unique=True)
    op.create_index(op.f('ix_response_actions_id'), 'response_actions', ['id'], unique=False)

    op.create_table('system_settings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('setting_key', sa.String(length=100), nullable=False),
        sa.Column('setting_value', sa.JSON(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_by', sa.String(length=50), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_system_settings_id'), 'system_settings', ['id'], unique=False)
    op.create_index(op.f('ix_system_settings_setting_key'), 'system_settings', ['setting_key'], unique=True)

    op.create_table('threat_intelligence',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ioc_type', sa.String(length=20), nullable=False),
        sa.Column('ioc_value', sa.String(length=500), nullable=False),
        sa.Column('source', sa.String(length=50), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_threat_intelligence_id'), 'threat_intelligence', ['id'], unique=False)

def downgrade():
    op.drop_index(op.f('ix_threat_intelligence_id'), table_name='threat_intelligence')
    op.drop_table('threat_intelligence')
    op.drop_index(op.f('ix_system_settings_setting_key'), table_name='system_settings')
    op.drop_index(op.f('ix_system_settings_id'), table_name='system_settings')
    op.drop_table('system_settings')
    op.drop_index(op.f('ix_response_actions_id'), table_name='response_actions')
    op.drop_index(op.f('ix_response_actions_action_id'), table_name='response_actions')
    op.drop_table('response_actions')
    op.drop_index(op.f('ix_ml_predictions_id'), table_name='ml_predictions')
    op.drop_index(op.f('ix_ml_predictions_event_id'), table_name='ml_predictions')
    op.drop_table('ml_predictions')
    op.drop_index(op.f('ix_attacker_profiles_ip_address'), table_name='attacker_profiles')
    op.drop_index(op.f('ix_attacker_profiles_id'), table_name='attacker_profiles')
    op.drop_table('attacker_profiles')
    op.drop_index(op.f('ix_attack_events_timestamp'), table_name='attack_events')
    op.drop_index(op.f('ix_attack_events_source_ip'), table_name='attack_events')
    op.drop_index(op.f('ix_attack_events_id'), table_name='attack_events')
    op.drop_index(op.f('ix_attack_events_event_id'), table_name='attack_events')
    op.drop_table('attack_events')
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_index(op.f('ix_users_id'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')