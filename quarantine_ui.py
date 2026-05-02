"""
Discord UI Components for Quarantine System
Provides interactive buttons for users to manage detected threats
"""

import discord
from discord import ui
from typing import Optional, Callable
import logging

logger = logging.getLogger('QuarantineUI')


class ThreatActionView(ui.View):
    """Interactive view for handling detected threats"""

    def __init__(self, user_id: int, threat_level: str, is_admin: bool = False, timeout: int = 300):
        super().__init__(timeout=timeout)
        self.user_id = user_id
        self.threat_level = threat_level
        self.is_admin = is_admin
        self.action = None

        # Customize buttons based on threat level
        if threat_level in ['critical', 'high']:
            # High risk - default to quarantine, allow admin override
            self.quarantine_btn.style = discord.ButtonStyle.danger
            self.quarantine_btn.label = "⚠️ Quarantine (Recommended)"

            if not is_admin:
                # Non-admins cannot keep critical/high threats
                self.keep_btn.disabled = True
                self.keep_btn.label = "❌ Keep (Admin Only)"
        else:
            # Medium/Low risk - user can choose
            self.keep_btn.style = discord.ButtonStyle.green

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        """Ensure only the original user (or admin) can interact"""
        if interaction.user.id == self.user_id:
            return True

        # Check if user is admin
        if interaction.user.guild_permissions.administrator:
            return True

        await interaction.response.send_message(
            "⚠️ Only the file uploader or an admin can make this choice.",
            ephemeral=True
        )
        return False

    @ui.button(label="✅ Keep File", style=discord.ButtonStyle.green, custom_id="keep")
    async def keep_btn(self, interaction: discord.Interaction, button: ui.Button):
        """User chooses to keep the file"""
        self.action = "keep"
        await interaction.response.edit_message(
            content=f"✅ {interaction.user.mention} chose to **KEEP** this file. "
                    f"Warning: This file was flagged as potentially malicious!",
            view=None
        )
        self.stop()

    @ui.button(label="🔒 Quarantine", style=discord.ButtonStyle.grey, custom_id="quarantine")
    async def quarantine_btn(self, interaction: discord.Interaction, button: ui.Button):
        """User chooses to quarantine the file"""
        self.action = "quarantine"
        await interaction.response.edit_message(
            content=f"🔒 {interaction.user.mention} quarantined this file. "
                    f"You can retrieve it later with `!quarantine list`",
            view=None
        )
        self.stop()

    @ui.button(label="🗑️ Delete Permanently", style=discord.ButtonStyle.red, custom_id="delete")
    async def delete_btn(self, interaction: discord.Interaction, button: ui.Button):
        """User chooses to delete the file permanently"""
        self.action = "delete"
        await interaction.response.edit_message(
            content=f"🗑️ {interaction.user.mention} **DELETED** this file permanently.",
            view=None
        )
        self.stop()

    async def on_timeout(self):
        """Handle timeout - auto-quarantine after timeout"""
        self.action = "timeout_quarantine"
        # View will be disabled by Discord automatically


class URLActionView(ui.View):
    """Interactive view for handling malicious URLs"""

    def __init__(self, user_id: int, url: str, is_admin: bool = False, timeout: int = 300):
        super().__init__(timeout=timeout)
        self.user_id = user_id
        self.url = url
        self.is_admin = is_admin
        self.action = None

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        """Ensure only the original user (or admin) can interact"""
        if interaction.user.id == self.user_id:
            return True

        if interaction.user.guild_permissions.administrator:
            return True

        await interaction.response.send_message(
            "⚠️ Only the message author or an admin can make this choice.",
            ephemeral=True
        )
        return False

    @ui.button(label="✅ Trust URL", style=discord.ButtonStyle.green, custom_id="trust_url")
    async def trust_btn(self, interaction: discord.Interaction, button: ui.Button):
        """User chooses to trust the URL - reveals actual URL"""
        self.action = "trust"
        await interaction.response.edit_message(
            content=f"✅ {interaction.user.mention} marked this URL as trusted.\n"
                    f"**⚠️ WARNING:** This URL was flagged by multiple security engines!\n\n"
                    f"**Original URL (at your own risk):**\n`{self.url}`\n\n"
                    f"🔗 **Clickable:** {self.url}",
            view=None
        )
        self.stop()

    @ui.button(label="🔒 Remove URL", style=discord.ButtonStyle.red, custom_id="remove_url")
    async def remove_btn(self, interaction: discord.Interaction, button: ui.Button):
        """User chooses to remove the URL"""
        self.action = "remove"
        await interaction.response.edit_message(
            content=f"🔒 {interaction.user.mention} removed the malicious URL from chat.",
            view=None
        )
        self.stop()

    async def on_timeout(self):
        """Handle timeout - auto-remove after timeout"""
        self.action = "timeout_remove"


class QuarantinePaginator(ui.View):
    """Paginator for quarantine list"""

    def __init__(self, items: list, items_per_page: int = 5, user_id: Optional[int] = None):
        super().__init__(timeout=180)
        self.items = items
        self.items_per_page = items_per_page
        self.current_page = 0
        self.user_id = user_id
        self.total_pages = (len(items) - 1) // items_per_page + 1 if items else 1

        # Disable buttons if only one page
        if self.total_pages <= 1:
            self.prev_btn.disabled = True
            self.next_btn.disabled = True
        else:
            self.prev_btn.disabled = True  # Start on first page

    def get_current_page_items(self):
        """Get items for current page"""
        start = self.current_page * self.items_per_page
        end = start + self.items_per_page
        return self.items[start:end]

    def create_embed(self) -> discord.Embed:
        """Create embed for current page"""
        embed = discord.Embed(
            title="🔒 Quarantine Storage",
            description=f"Page {self.current_page + 1}/{self.total_pages} • {len(self.items)} total items",
            color=discord.Color.orange()
        )

        page_items = self.get_current_page_items()

        if not page_items:
            embed.add_field(
                name="No Items",
                value="The quarantine is empty.",
                inline=False
            )
        else:
            for item in page_items:
                # Parse item data
                item_type_emoji = "📄" if item.item_type == "file" else "🔗"
                threat_emoji = {
                    'critical': '☠️',
                    'high': '🚨',
                    'medium': '⚠️',
                    'low': '🟦',
                    'safe': '✅'
                }.get(item.threat_level, '❓')

                value_text = (
                    f"**Type:** {item_type_emoji} {item.item_type.upper()}\n"
                    f"**Threat:** {threat_emoji} {item.threat_level.upper()} ({item.threat_score:.1f}/100)\n"
                    f"**User:** <@{item.user_id}>\n"
                    f"**Date:** {item.quarantine_timestamp[:10]}\n"
                    f"**Retrieved:** {'✅ Yes' if item.retrieved else '❌ No'}"
                )

                embed.add_field(
                    name=f"ID: {item.id} - {item.filename[:30]}",
                    value=value_text,
                    inline=False
                )

        embed.set_footer(text="Use !quarantine retrieve <ID> to restore an item")
        return embed

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        """Allow only the original user or admins"""
        if self.user_id and interaction.user.id != self.user_id:
            if not interaction.user.guild_permissions.administrator:
                await interaction.response.send_message(
                    "⚠️ Only admins can navigate quarantine pages.",
                    ephemeral=True
                )
                return False
        return True

    @ui.button(label="◀️ Previous", style=discord.ButtonStyle.grey, custom_id="prev")
    async def prev_btn(self, interaction: discord.Interaction, button: ui.Button):
        """Go to previous page"""
        self.current_page -= 1

        # Update button states
        self.next_btn.disabled = False
        if self.current_page == 0:
            self.prev_btn.disabled = True

        embed = self.create_embed()
        await interaction.response.edit_message(embed=embed, view=self)

    @ui.button(label="▶️ Next", style=discord.ButtonStyle.grey, custom_id="next")
    async def next_btn(self, interaction: discord.Interaction, button: ui.Button):
        """Go to next page"""
        self.current_page += 1

        # Update button states
        self.prev_btn.disabled = False
        if self.current_page >= self.total_pages - 1:
            self.next_btn.disabled = True

        embed = self.create_embed()
        await interaction.response.edit_message(embed=embed, view=self)

    @ui.button(label="🔄 Refresh", style=discord.ButtonStyle.green, custom_id="refresh")
    async def refresh_btn(self, interaction: discord.Interaction, button: ui.Button):
        """Refresh the current page"""
        embed = self.create_embed()
        await interaction.response.edit_message(embed=embed, view=self)


class RetrieveConfirmView(ui.View):
    """Confirmation view for retrieving quarantined items"""

    def __init__(self, user_id: int, item_id: int, filename: str):
        super().__init__(timeout=60)
        self.user_id = user_id
        self.item_id = item_id
        self.filename = filename
        self.confirmed = False

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        """Ensure only the original user can confirm"""
        if interaction.user.id == self.user_id:
            return True

        if interaction.user.guild_permissions.administrator:
            return True

        await interaction.response.send_message(
            "⚠️ You cannot retrieve this item.",
            ephemeral=True
        )
        return False

    @ui.button(label="✅ Yes, Retrieve", style=discord.ButtonStyle.green, custom_id="confirm")
    async def confirm_btn(self, interaction: discord.Interaction, button: ui.Button):
        """Confirm retrieval"""
        self.confirmed = True
        await interaction.response.edit_message(
            content=f"✅ Retrieving quarantined item...",
            view=None
        )
        self.stop()

    @ui.button(label="❌ Cancel", style=discord.ButtonStyle.red, custom_id="cancel")
    async def cancel_btn(self, interaction: discord.Interaction, button: ui.Button):
        """Cancel retrieval"""
        self.confirmed = False
        await interaction.response.edit_message(
            content=f"❌ Retrieval cancelled.",
            view=None
        )
        self.stop()
