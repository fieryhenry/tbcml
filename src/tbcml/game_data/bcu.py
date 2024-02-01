import enum
import os
from typing import Any, Optional
import tbcml


class BCUFileGroup:
    def __init__(self, bcu_files: list["BCUFile"]) -> None:
        """
        Initialize a BCUFileGroup object.

        Args:
            bcu_files (list[BCUFile]): The list of BCU files.
        """
        self.bcu_files = bcu_files

    def get_file_by_name(self, name: str) -> Optional["BCUFile"]:
        """
        Get a BCU file by name.

        Args:
            name (str): The name of the file.

        Returns:
            Optional[BCUFile]: The BCU file.
        """
        for bcu_file in self.bcu_files:
            if bcu_file.name == name:
                return bcu_file
        return None

    def get_files_by_prefix(self, prefix: str) -> list["BCUFile"]:
        """
        Get a list of BCU files by prefix.

        Args:
            prefix (str): The prefix of the file.

        Returns:
            list[BCUFile]: The list of BCU files.
        """
        files: list[BCUFile] = []
        for bcu_file in self.bcu_files:
            if bcu_file.name.startswith(prefix):
                files.append(bcu_file)
        return files


class BCUForm:
    def __init__(
        self,
        form_data: dict[str, Any],
        anims: "BCUFileGroup",
        cat_id: int,
        form: "tbcml.CatFormType",
    ):
        self.form_data = form_data
        self.cat_id = cat_id
        self.form = form
        self.id = self.form_data["anim"]["id"]
        self.name = self.form_data["names"]["dat"][0]["val"]
        self.description = self.form_data["description"]["dat"][0]["val"].split("<br>")
        self.anims = anims
        anim = self.load_anim()
        if anim is None:
            return None
        self.anim = anim

        upgrade_icon = self.load_display_icon()
        if upgrade_icon is None:
            return None
        self.upgrade_icon = upgrade_icon

        deploy_icon = self.load_deploy_icon()
        if deploy_icon is None:
            return None
        self.deploy_icon = deploy_icon

    def get_cat_id_form(self) -> Optional[tuple[int, "tbcml.CatFormType"]]:
        img_name = self.anim.texture.metadata.img_name
        if img_name is None:
            raise ValueError("anim texture img_name cannot be None!")
        cat_id = int(img_name[:3])
        form_str = img_name[4:5]
        try:
            form_type = tbcml.CatFormType(form_str)
        except ValueError:
            return None
        return cat_id, form_type

    def get_mamodel_name(self) -> str:
        return f"{self.get_cat_id_str()}_{self.form.value}.mamodel"

    def get_imgcut_name(self) -> str:
        return f"{self.get_cat_id_str()}_{self.form.value}.imgcut"

    def get_sprite_name(self) -> str:
        return f"{self.get_cat_id_str()}_{self.form.value}.png"

    def get_maanim_names(self) -> list[str]:
        maanims = self.anims.get_files_by_prefix("maanim")
        maanim_names: list[str] = []
        for maanim in maanims:
            maanim_id = tbcml.AnimType.from_bcu_str(maanim.name)
            if maanim_id is None:
                continue
            index_str = tbcml.PaddedInt(maanim_id.value, 2).to_str()
            maanim_names.append(
                f"{self.get_cat_id_str()}_{self.form.value}{index_str}.maanim"
            )
        return maanim_names

    def get_maanim_data(self) -> list["tbcml.Data"]:
        maanims = self.anims.get_files_by_prefix("maanim")
        maanim_data: list["tbcml.Data"] = []
        for maanim in maanims:
            maanim_id = tbcml.AnimType.from_bcu_str(maanim.name)
            if maanim_id is None:
                continue
            maanim_data.append(maanim.data)
        return maanim_data

    def load_anim(self) -> Optional["tbcml.Model"]:
        sprite = self.anims.get_file_by_name("sprite.png")
        imgcut = self.anims.get_file_by_name("imgcut.txt")
        mamodel = self.anims.get_file_by_name("mamodel.txt")
        if sprite is None or imgcut is None or mamodel is None:
            return None
        model = tbcml.Model().read_data(
            self.get_sprite_name(),
            sprite.data,
            self.get_imgcut_name(),
            imgcut.data,
            self.get_maanim_names(),
            self.get_maanim_data(),
            self.get_mamodel_name(),
            mamodel.data,
        )
        return model

    def load_display_icon(self) -> Optional["tbcml.BCImage"]:
        display_file = self.anims.get_file_by_name("icon_display.png")
        if display_file is None:
            return None

        return tbcml.BCImage.from_data(display_file.data)

    def load_deploy_icon(self) -> Optional["tbcml.BCImage"]:
        deploy_file = self.anims.get_file_by_name("icon_deploy.png")
        if deploy_file is None:
            return None

        return tbcml.BCImage.from_data(deploy_file.data)

    def get_cat_id_str(self):
        return tbcml.PaddedInt(self.cat_id, 3).to_str()

    def to_cat_form(self, cat_id: int, form: "tbcml.CatFormType") -> "tbcml.CatForm":
        self.cat_id = cat_id
        self.form = form
        self.anim.mamodel.dup_ints()
        frm = tbcml.CatForm(self.form)
        frm.stats = self.to_stats()
        frm.name = self.name
        frm.description = self.description
        frm.anim = self.anim
        frm.upgrade_icon = self.upgrade_icon
        frm.deploy_icon = self.deploy_icon
        frm.set_cat_id(self.cat_id)
        frm.set_form(self.form)
        frm.format_bcu_deploy_icon()
        frm.format_bcu_upgrade_icon()
        return frm

    def to_stats(self) -> "tbcml.FormStats":
        stats = tbcml.FormStats()
        base_stats = self.form_data["du"]
        traits = base_stats["traits"]
        procs = base_stats["rep"]["proc"]
        traits = sorted(traits, key=lambda x: x["id"])
        stats.hp = base_stats["hp"]
        stats.kbs = base_stats["hb"]
        stats.speed = base_stats["speed"]
        stats.attack_1_damage = base_stats["atks"]["pool"][0]["atk"]
        stats.attack_interval = base_stats["tba"] // 2
        stats.attack_range = base_stats["range"]
        stats.cost = base_stats["price"]
        stats.recharge_time = base_stats["resp"] // 2
        stats.collision_width = base_stats["width"]
        stats.target_red = self.get_trait_by_id(traits, 0)
        stats.area_attack = base_stats["atks"]["pool"][0]["range"]
        stats.min_z_layer = base_stats["front"]
        stats.max_z_layer = base_stats["back"]
        stats.target_floating = self.get_trait_by_id(traits, 1)
        stats.target_black = self.get_trait_by_id(traits, 2)
        stats.target_metal = self.get_trait_by_id(traits, 3)
        stats.target_traitless = self.get_trait_by_id(traits, 9)
        stats.target_angel = self.get_trait_by_id(traits, 4)
        stats.target_alien = self.get_trait_by_id(traits, 5)
        stats.target_zombie = self.get_trait_by_id(traits, 6)
        stats.strong = self.check_ability(base_stats["abi"], 0)
        stats.knockback_prob = self.get_proc_prob(procs, "KB")
        stats.freeze_prob = self.get_proc_prob(procs, "STOP")
        stats.freeze_duration = self.get_proc_time(procs, "STOP")
        stats.slow_prob = self.get_proc_prob(procs, "SLOW")
        stats.slow_duration = self.get_proc_time(procs, "SLOW")
        stats.resistant = self.check_ability(base_stats["abi"], 1)
        stats.insane_damage = self.check_ability(base_stats["abi"], 2)
        stats.crit_prob = self.get_proc_prob(procs, "CRIT")
        stats.attacks_only = self.check_ability(base_stats["abi"], 3)
        stats.extra_money = bool(self.get_proc_mult(procs, "BOUNTY") // 100)
        stats.base_destroyer = bool(self.get_proc_mult(procs, "ATKBASE") // 300)
        stats.wave_level = max(
            self.get_proc_level(procs, "WAVE"),
            self.get_proc_level(procs, "MINIWAVE"),
        )
        stats.weaken_prob = self.get_proc_prob(procs, "WEAK")
        stats.weaken_duration = self.get_proc_time(procs, "WEAK")
        stats.strengthen_hp_start_percentage = self.get_proc_health(procs, "STRONG")
        stats.strengthen_hp_boost_percentage = self.get_proc_mult(procs, "STRONG")
        stats.lethal_strike_prob = self.get_proc_prob(procs, "LETHAL")
        stats.is_metal = self.check_ability(base_stats["abi"], 4)
        stats.attack_1_ld_start = base_stats["atks"]["pool"][0]["ld0"]
        stats.attack_1_ld_range = (
            base_stats["atks"]["pool"][0]["ld1"] - stats.attack_1_ld_start
        )
        stats.wave_immunity = bool(self.get_proc_mult(procs, "IMUWAVE"))
        stats.wave_blocker = self.check_ability(base_stats["abi"], 5)
        stats.knockback_immunity = bool(self.get_proc_mult(procs, "IMUKB"))
        stats.freeze_immunity = bool(self.get_proc_mult(procs, "IMUSTOP"))
        stats.slow_immunity = bool(self.get_proc_mult(procs, "IMUSLOW"))
        stats.weaken_immunity = bool(self.get_proc_mult(procs, "IMUWEAK"))
        stats.zombie_killer = self.check_ability(base_stats["abi"], 9)
        stats.witch_killer = self.check_ability(base_stats["abi"], 10)
        stats.target_witch = self.check_ability(base_stats["abi"], 10)
        stats.attacks_before_set_attack_state = base_stats["loop"]
        stats.attack_state = 2 if self.check_ability(base_stats["abi"], 11) else 0
        stats.attack_2_damage = self.get_attack(base_stats["atks"]["pool"], 1, "atk")
        stats.attack_2_damage = self.get_attack(base_stats["atks"]["pool"], 2, "atk")
        stats.attack_1_foreswing = self.get_attack(base_stats["atks"]["pool"], 0, "pre")
        stats.attack_2_foreswing = self.get_attack(base_stats["atks"]["pool"], 1, "pre")
        stats.attack_2_foreswing = self.get_attack(base_stats["atks"]["pool"], 2, "pre")
        stats.attack_2_use_ability = True
        stats.attack_2_use_ability = True
        stats.soul_model_anim_id = base_stats["death"]["id"]
        stats.barrier_break_prob = self.get_proc_prob(procs, "BREAK")
        stats.warp_prob = self.get_proc_prob(procs, "WARP")
        stats.warp_duration = self.get_proc_time(procs, "WARP")
        stats.warp_min_range = self.get_proc_value(procs, "WARP", "dis") * 4
        stats.warp_max_range = self.get_proc_value(procs, "WARP", "dis") * 4
        stats.warp_blocker = bool(self.get_proc_mult(procs, "IMUWARP"))
        stats.target_eva = self.check_ability(base_stats["abi"], 13)
        stats.eva_killer = self.check_ability(base_stats["abi"], 13)
        stats.target_relic = self.get_trait_by_id(traits, 8)
        stats.curse_immunity = bool(self.get_proc_mult(procs, "IMUCURSE"))
        stats.insanely_tough = self.check_ability(base_stats["abi"], 15)
        stats.insane_damage = self.check_ability(base_stats["abi"], 16)
        stats.savage_blow_prob = self.get_proc_prob(procs, "SATK")
        stats.savage_blow_damage_addition = self.get_proc_mult(procs, "SATK")
        stats.dodge_prob = self.get_proc_prob(procs, "IMUATK")
        stats.dodge_duration = self.get_proc_time(procs, "IMUATK")
        stats.surge_prob = self.get_proc_prob(procs, "VOLC")
        stats.surge_start = int(self.get_proc_value(procs, "VOLC", "dis_0")) * 4
        stats.surge_range = (
            int(self.get_proc_value(procs, "VOLC", "dis_1")) * 4
        ) - stats.surge_start
        stats.surge_level = self.get_proc_value(procs, "VOLC", "time") // 20
        stats.toxic_immunity = bool(self.get_proc_mult(procs, "IMUPOIATK"))
        stats.surge_immunity = bool(self.get_proc_mult(procs, "IMUVOLC"))
        stats.curse_prob = self.get_proc_prob(procs, "CURSE")
        stats.curse_duration = self.get_proc_time(procs, "CURSE")
        stats.wave_is_mini = self.get_proc_prob(procs, "MINIWAVE") != 0
        stats.shield_pierce_prob = self.get_proc_prob(procs, "SHIELDBREAK")
        stats.target_aku = self.get_trait_by_id(traits, 7)
        stats.collossus_slayer = self.check_ability(base_stats["abi"], 17)
        stats.soul_strike = self.check_ability(base_stats["abi"], 18)
        stats.attack_2_ld_flag = (
            self.get_attack(base_stats["atks"]["pool"], 1, "ld") != 0
        )
        stats.attack_2_ld_start = self.get_attack(base_stats["atks"]["pool"], 1, "ld0")
        stats.attack_2_ld_range = (
            self.get_attack(base_stats["atks"]["pool"], 1, "ld1")
            - stats.attack_2_ld_start
        )
        stats.attack_2_ld_flag = (
            self.get_attack(base_stats["atks"]["pool"], 2, "ld") != 0
        )
        stats.attack_2_ld_start = self.get_attack(base_stats["atks"]["pool"], 2, "ld0")
        stats.attack_2_ld_range = (
            self.get_attack(base_stats["atks"]["pool"], 2, "ld1")
            - stats.attack_2_ld_start
        )
        stats.behemoth_slayer = self.get_proc_prob(procs, "BSTHUNT") != 0
        stats.behemoth_dodge_prob = self.get_proc_prob(procs, "BSTHUNT")
        stats.behemoth_dodge_duration = self.get_proc_time(procs, "BSTHUNT")
        stats.attack_1_use_ability = True
        stats.counter_surge = self.check_ability(base_stats["abi"], 19)
        stats.summon_id = BCUForm.get_proc_value(procs, "SPIRIT", "id")
        stats.sage_slayer = self.check_ability(base_stats["abi"], 20)

        return stats

    @staticmethod
    def get_trait_by_id(traits: list[dict[str, Any]], id: int) -> bool:
        for trait in traits:
            if trait["id"] == id:
                return True
        return False

    @staticmethod
    def check_ability(abi: int, id: int) -> bool:
        has_ability = abi & (1 << id) != 0
        return has_ability

    @staticmethod
    def get_proc_value(procs: dict[str, dict[str, int]], proc_name: str, key: str):
        if proc_name in procs:
            return int(procs[proc_name][key])
        return 0

    @staticmethod
    def get_proc_prob(procs: dict[str, dict[str, int]], proc_name: str):
        return BCUForm.get_proc_value(procs, proc_name, "prob")

    @staticmethod
    def get_proc_time(procs: dict[str, dict[str, int]], proc_name: str):
        return BCUForm.get_proc_value(procs, proc_name, "time")

    @staticmethod
    def get_proc_level(procs: dict[str, dict[str, int]], proc_name: str):
        return BCUForm.get_proc_value(procs, proc_name, "lv")

    @staticmethod
    def get_proc_health(procs: dict[str, dict[str, int]], proc_name: str):
        return BCUForm.get_proc_value(procs, proc_name, "health")

    @staticmethod
    def get_proc_mult(procs: dict[str, dict[str, int]], proc_name: str):
        return BCUForm.get_proc_value(procs, proc_name, "mult")

    @staticmethod
    def get_attack(attack_data: list[dict[str, Any]], attack_id: int, key: str):
        try:
            return attack_data[attack_id][key]
        except IndexError:
            return 0


class BCUCat:
    def __init__(
        self,
        unit_data: dict[str, Any],
        anims: list[list["BCUFile"]],
        cat_id: int,
    ):
        self.unit_data = unit_data
        forms = self.unit_data["val"]["forms"]
        self.local_id = self.unit_data["val"]["id"]["id"]
        self.rarity = self.unit_data["val"]["rarity"]
        self.max_base_level = self.unit_data["val"]["max"]
        self.max_plus_level = self.unit_data["val"]["maxp"]
        self.anims = anims
        self.forms: list[BCUForm] = []
        for i, (form_data, form_anims) in enumerate(zip(forms, anims)):
            self.forms.append(
                BCUForm(
                    form_data,
                    BCUFileGroup(form_anims),
                    cat_id,
                    tbcml.CatFormType.from_index(i),
                )
            )

    def to_cat(
        self,
        cat_id: int,
    ) -> "tbcml.Cat":
        forms: dict[tbcml.CatFormType, tbcml.CatForm] = {}
        for form in self.forms:
            forms[form.form] = form.to_cat_form(cat_id, form.form)

        unit_buy = tbcml.UnitBuy()

        unit_buy.rarity = self.rarity
        unit_buy.max_base_no_catseye = self.max_base_level
        unit_buy.max_plus = self.max_plus_level
        unit_buy.max_base_catseye = self.max_base_level
        unit_buy.set_obtainable(True)

        nypb = tbcml.NyankoPictureBook()
        nypb.is_displayed_in_cat_guide = True

        unit = tbcml.Cat(
            cat_id,
        )
        unit.forms = forms
        unit.unitbuy = unit_buy
        unit.set_cat_id(cat_id)
        return unit

    def get_cat_id(self) -> int:
        for form in self.forms:
            return form.cat_id
        return -1


class BCUEnemy:
    def __init__(
        self, enemy_data: dict[str, Any], anims: "BCUFileGroup", enemy_id: int
    ):
        self.enemy_data = enemy_data
        self.enemy_id = enemy_id
        self.anims = anims
        self.id = self.enemy_data["anim"]["id"]
        self.local_id = self.enemy_data["id"]["id"]
        self.name = self.enemy_data["names"]["dat"][0]["val"]
        self.descritpion = self.enemy_data["description"]["dat"][0]["val"].split("<br>")
        anim = self.load_anim()
        if anim is None:
            return None
        self.anim = anim

    def get_mamodel_name(self) -> str:
        return f"{self.get_enemy_id_str()}_e.mamodel"

    def get_imgcut_name(self) -> str:
        return f"{self.get_enemy_id_str()}_e.imgcut"

    def get_sprite_name(self) -> str:
        return f"{self.get_enemy_id_str()}_e.png"

    def get_maanim_names(self) -> list[str]:
        maanims = self.anims.get_files_by_prefix("maanim")
        maanim_names: list[str] = []
        for maanim in maanims:
            maanim_id = tbcml.AnimType.from_bcu_str(maanim.name)
            if maanim_id is None:
                continue
            index_str = tbcml.PaddedInt(maanim_id.value, 2).to_str()
            maanim_names.append(f"{self.get_enemy_id_str()}_e{index_str}.maanim")
        return maanim_names

    def get_maanim_data(self) -> list["tbcml.Data"]:
        maanims = self.anims.get_files_by_prefix("maanim")
        maanim_data: list["tbcml.Data"] = []
        for maanim in maanims:
            maanim_id = tbcml.AnimType.from_bcu_str(maanim.name)
            if maanim_id is None:
                continue
            maanim_data.append(maanim.data)
        return maanim_data

    def load_anim(self) -> Optional["tbcml.Model"]:
        sprite = self.anims.get_file_by_name("sprite.png")
        imgcut = self.anims.get_file_by_name("imgcut.txt")
        mamodel = self.anims.get_file_by_name("mamodel.txt")
        if sprite is None or imgcut is None or mamodel is None:
            return None
        model = tbcml.Model().read_data(
            self.get_sprite_name(),
            sprite.data,
            self.get_imgcut_name(),
            imgcut.data,
            self.get_maanim_names(),
            self.get_maanim_data(),
            self.get_mamodel_name(),
            mamodel.data,
        )
        return model

    def get_enemy_id(self) -> Optional[int]:
        img_name = self.anim.texture.metadata.img_name
        if img_name is None:
            return None
        try:
            enemy_id = int(img_name[:3])
        except ValueError:
            return None
        return enemy_id

    def get_enemy_id_str(self):
        return tbcml.PaddedInt(self.enemy_id, 3).to_str()

    def to_enemy(self, enemy_id: int) -> "tbcml.Enemy":
        for maanim in self.anim.anims:
            if maanim.name is None:
                continue
            index = tbcml.AnimType.from_bcu_str(maanim.name)
            if index is None:
                continue
            index_str = tbcml.PaddedInt(index.value, 2).to_str()
            maanim.name = f"{self.get_enemy_id_str()}_e{index_str}.maanim"
        enemy = tbcml.Enemy(
            enemy_id,
        )
        enemy.stats = self.to_stats()
        enemy.name = self.name
        enemy.description = self.descritpion
        enemy.anim = self.anim
        enemy.set_enemy_id(enemy_id)
        return enemy

    def to_stats(self) -> "tbcml.EnemyStats":
        stats = tbcml.EnemyStats()
        base_stats = self.enemy_data["de"]
        traits = base_stats["traits"]
        procs = base_stats["rep"]["proc"]
        traits = sorted(traits, key=lambda x: x["id"])

        stats.hp = base_stats["hp"]
        stats.kbs = base_stats["hb"]
        stats.speed = base_stats["speed"]
        stats.attack_1_damage = base_stats["atks"]["pool"][0]["atk"]
        stats.attack_interval = base_stats["tba"]
        stats.attack_range = base_stats["range"]
        stats.money_drop = base_stats["drop"]
        stats.collision_width = base_stats["width"]
        stats.red = BCUForm.get_trait_by_id(traits, 0)
        stats.area_attack = base_stats["atks"]["pool"][0]["range"]
        stats.floating = BCUForm.get_trait_by_id(traits, 1)
        stats.black = BCUForm.get_trait_by_id(traits, 2)
        stats.metal = BCUForm.get_trait_by_id(traits, 3)
        stats.traitless = BCUForm.get_trait_by_id(traits, 9)
        stats.angel = BCUForm.get_trait_by_id(traits, 4)
        stats.alien = BCUForm.get_trait_by_id(traits, 5)
        stats.zombie = BCUForm.get_trait_by_id(traits, 6)
        stats.knockback_prob = BCUForm.get_proc_prob(procs, "KB")
        stats.freeze_prob = BCUForm.get_proc_prob(procs, "STOP")
        stats.freeze_duration = BCUForm.get_proc_time(procs, "STOP")
        stats.slow_prob = BCUForm.get_proc_prob(procs, "SLOW")
        stats.slow_duration = BCUForm.get_proc_time(procs, "SLOW")
        stats.crit_prob = BCUForm.get_proc_prob(procs, "CRIT")
        stats.base_destroyer = bool(BCUForm.get_proc_mult(procs, "ATKBASE") // 300)
        stats.wave_is_mini = bool(
            max(
                BCUForm.get_proc_prob(procs, "WAVE"),
                BCUForm.get_proc_prob(procs, "MINIWAVE"),
            )
        )
        stats.wave_level = max(
            BCUForm.get_proc_level(procs, "WAVE"),
            BCUForm.get_proc_level(procs, "MINIWAVE"),
        )
        stats.weaken_prob = BCUForm.get_proc_prob(procs, "WEAK")
        stats.weaken_duration = BCUForm.get_proc_time(procs, "WEAK")
        stats.strengthen_hp_start_percentage = BCUForm.get_proc_health(procs, "STRONG")
        stats.strengthen_hp_boost_percentage = BCUForm.get_proc_mult(procs, "STRONG")
        stats.survive_lethal_strike_prob = BCUForm.get_proc_prob(procs, "LETHAL")
        stats.attack_1_ld_start = base_stats["atks"]["pool"][0]["ld0"]
        stats.attack_1_ld_range = (
            base_stats["atks"]["pool"][0]["ld1"] - stats.attack_1_ld_start
        )
        stats.wave_immunity = bool(BCUForm.get_proc_mult(procs, "IMUWAVE"))
        stats.wave_blocker = BCUForm.check_ability(base_stats["abi"], 5)
        stats.knockback_immunity = bool(BCUForm.get_proc_mult(procs, "IMUKB"))
        stats.freeze_immunity = bool(BCUForm.get_proc_mult(procs, "IMUSTOP"))
        stats.slow_immunity = bool(BCUForm.get_proc_mult(procs, "IMUSLOW"))
        stats.weaken_immunity = bool(BCUForm.get_proc_mult(procs, "IMUWEAK"))
        stats.burrow_count = BCUForm.get_proc_value(procs, "BURROW", "count")
        stats.burrow_distance = BCUForm.get_proc_value(procs, "BURROW", "dis") * 4
        stats.revive_count = BCUForm.get_proc_value(procs, "REVIVE", "count")
        stats.revive_time = BCUForm.get_proc_time(procs, "REVIVE")
        stats.revive_hp_percentage = BCUForm.get_proc_health(procs, "REVIVE")
        stats.witch = BCUForm.get_trait_by_id(traits, 10)
        stats.base = BCUForm.get_trait_by_id(traits, 14)
        stats.attacks_before_set_attack_state = base_stats["loop"]
        stats.attack_state = 2 if BCUForm.check_ability(base_stats["abi"], 11) else 0
        stats.attack_2_damage = BCUForm.get_attack(base_stats["atks"]["pool"], 1, "atk")
        stats.attack_2_damage = BCUForm.get_attack(base_stats["atks"]["pool"], 2, "atk")
        stats.attack_1_foreswing = BCUForm.get_attack(
            base_stats["atks"]["pool"], 0, "pre"
        )
        stats.attack_2_foreswing = BCUForm.get_attack(
            base_stats["atks"]["pool"], 1, "pre"
        )
        stats.attack_2_foreswing = BCUForm.get_attack(
            base_stats["atks"]["pool"], 2, "pre"
        )
        stats.attack_2_use_ability = True
        stats.attack_2_use_ability = True
        stats.soul_model_anim_id = base_stats["death"]["id"]
        stats.barrier_hp = BCUForm.get_proc_health(procs, "BARRIER")
        stats.warp_prob = BCUForm.get_proc_prob(procs, "WARP")
        stats.warp_duration = BCUForm.get_proc_time(procs, "WARP")
        stats.warp_min_range = BCUForm.get_proc_value(procs, "WARP", "dis") * 4
        stats.warp_max_range = BCUForm.get_proc_value(procs, "WARP", "dis") * 4
        stats.starred_alien = base_stats["star"]
        stats.warp_blocker = bool(BCUForm.get_proc_mult(procs, "IMUWARP"))
        stats.eva_angel = BCUForm.get_trait_by_id(traits, 10)
        stats.relic = BCUForm.get_trait_by_id(traits, 8)
        stats.curse_prob = BCUForm.get_proc_prob(procs, "CURSE")
        stats.curse_duration = BCUForm.get_proc_time(procs, "CURSE")
        stats.surge_prob = BCUForm.get_proc_prob(procs, "VOLC")
        stats.savage_blow_prob = BCUForm.get_proc_prob(procs, "SATK")
        stats.savage_blow_damage_addition = BCUForm.get_proc_mult(procs, "SATK")
        stats.dodge_prob = BCUForm.get_proc_prob(procs, "IMUATK")
        stats.dodge_duration = BCUForm.get_proc_time(procs, "IMUATK")
        stats.toxic_prob = BCUForm.get_proc_prob(procs, "POIATK")
        stats.toxic_hp_percentage = BCUForm.get_proc_mult(procs, "POIATK")
        stats.surge_start = int(BCUForm.get_proc_value(procs, "VOLC", "dis_0")) * 4
        stats.surge_range = (
            int(BCUForm.get_proc_value(procs, "VOLC", "dis_1")) * 4
        ) - stats.surge_start
        stats.surge_level = BCUForm.get_proc_value(procs, "VOLC", "time") // 20
        stats.surge_immunity = bool(BCUForm.get_proc_mult(procs, "IMUVOLC"))
        stats.wave_is_mini = BCUForm.get_proc_prob(procs, "MINIWAVE") != 0
        stats.shield_hp = BCUForm.get_proc_health(procs, "SHIELD")
        stats.sheild_kb_heal_percentage = BCUForm.get_proc_value(
            procs, "SHIELD", "regen"
        )
        stats.death_surge_prob = BCUForm.get_proc_prob(procs, "DEATHSURGE")
        stats.death_surge_start = (
            int(BCUForm.get_proc_value(procs, "DEATHSURGE", "dis_0")) * 4
        )
        stats.death_surge_range = (
            int(BCUForm.get_proc_value(procs, "DEATHSURGE", "dis_1")) * 4
        ) - stats.death_surge_start
        stats.death_surge_level = (
            BCUForm.get_proc_value(procs, "DEATHSURGE", "time") // 20
        )
        stats.aku = BCUForm.get_trait_by_id(traits, 7)
        stats.baron = BCUForm.get_trait_by_id(traits, 12)
        stats.attack_2_ld_flag = (
            BCUForm.get_attack(base_stats["atks"]["pool"], 1, "ld0") != 0
            or BCUForm.get_attack(base_stats["atks"]["pool"], 1, "ld1") != 0
        )
        stats.attack_2_ld_start = BCUForm.get_attack(
            base_stats["atks"]["pool"], 1, "ld0"
        )
        stats.attack_2_ld_range = (
            BCUForm.get_attack(base_stats["atks"]["pool"], 1, "ld1")
            - stats.attack_2_ld_start
        )
        stats.attack_2_ld_flag = (
            BCUForm.get_attack(base_stats["atks"]["pool"], 2, "ld0") != 0
            or BCUForm.get_attack(base_stats["atks"]["pool"], 2, "ld1") != 0
        )
        stats.attack_2_ld_start = BCUForm.get_attack(
            base_stats["atks"]["pool"], 2, "ld0"
        )
        stats.attack_2_ld_range = (
            BCUForm.get_attack(base_stats["atks"]["pool"], 2, "ld1")
            - stats.attack_2_ld_start
        )
        stats.behemoth = BCUForm.get_trait_by_id(traits, 13)
        stats.counter_surge = BCUForm.check_ability(base_stats["abi"], 19)

        return stats


class BCUFileTypes(enum.Enum):
    ANIMS = "animations"
    MUSIC = "musics"
    PACK = "pack.json"


class BCUFile:
    def __init__(
        self,
        file_info: dict[str, Any],
        enc_data: "tbcml.Data",
        key: "tbcml.Data",
        iv: "tbcml.Data",
    ):
        self.path: str = file_info["path"]
        self.size = file_info["size"]
        self.offset = file_info["offset"]
        self.name = os.path.basename(self.path)
        self.type_str = self.path.split("/")[1]
        self.key = key
        self.iv = iv
        self.padded_size = self.size + (16 - self.size % 16)
        self.enc_data = enc_data[self.offset : self.offset + self.padded_size]
        self.data = self.decrypt()

    def get_type(self) -> Optional[BCUFileTypes]:
        try:
            return BCUFileTypes(self.type_str)
        except ValueError:
            return None

    def decrypt(self) -> "tbcml.Data":
        aes = tbcml.AesCipher(self.key.to_bytes(), self.iv.to_bytes())
        data = aes.decrypt(self.enc_data)
        return data[: self.size]


class BCUZip:
    def __init__(
        self,
        enc_data: "tbcml.Data",
    ):
        self.enc_data = enc_data
        self.iv, self.key = self.get_iv_key()
        self.json, self.enc_file_data = self.decrypt()
        self.read_json_info()
        self.files = self.load_files()
        pack_json = self.load_pack_json()
        if pack_json is None:
            raise ValueError("Pack json not found")
        self.pack_json = pack_json
        self.cats = self.load_units()
        self.enemies = self.load_enemies()

    @staticmethod
    def from_path(path: "tbcml.Path") -> "BCUZip":
        return BCUZip(tbcml.Data.from_file(path))

    def get_iv_key(self) -> tuple["tbcml.Data", "tbcml.Data"]:
        iv_str = "battlecatsultimate"
        iv = tbcml.Hash(tbcml.HashAlgorithm.MD5).get_hash(tbcml.Data(iv_str))
        key = self.enc_data[0x10:0x20]
        return iv, key

    def decrypt(self) -> tuple["tbcml.JsonFile", "tbcml.Data"]:
        json_length = self.enc_data[0x20:0x24].to_int_little()
        json_length_pad = 16 * (json_length // 16 + 1)
        json_data = self.enc_data[0x24 : 0x24 + json_length_pad]
        aes = tbcml.AesCipher(self.key.to_bytes(), self.iv.to_bytes())
        json_data = aes.decrypt(json_data)
        json_data = json_data[0:json_length]

        enc_file_data = self.enc_data[0x24 + json_length_pad :]

        json = tbcml.JsonFile.from_data(json_data)

        return json, enc_file_data

    def read_json_info(self):
        self.desc = self.json["desc"]
        self.files_data = self.json["files"]

        self.bcu_version = self.desc["BCU_VERSION"]
        self.id = self.desc["id"]
        self.author = self.desc["author"]
        self.names = self.desc["names"]
        self.allow_anim = self.desc["allowAnim"]
        self.dependency = self.desc["dependency"]

    def load_files(self) -> list[BCUFile]:
        files: list[BCUFile] = []
        for file_info in self.files_data:
            files.append(BCUFile(file_info, self.enc_file_data, self.key, self.iv))
        return files

    def get_file(self, path: str) -> Optional[BCUFile]:
        for file in self.files:
            if file.path == path:
                return file
        return None

    def get_file_by_name(self, name: str) -> Optional[BCUFile]:
        for file in self.files:
            if file.name == name:
                return file
        return None

    def get_files_by_type(self, type: BCUFileTypes) -> list[BCUFile]:
        files: list[BCUFile] = []
        for file in self.files:
            if file.get_type() == type:
                files.append(file)
        return files

    def get_files_by_dir(self, dir: str) -> list[BCUFile]:
        files: list[BCUFile] = []
        for file in self.files:
            if os.path.basename(os.path.dirname(file.path)) == dir:
                files.append(file)
        return files

    def extract(self, output_dir: "tbcml.Path"):
        output_dir = output_dir.add(self.get_name())
        for file in self.files:
            file_path = output_dir.add(file.path)
            file_dir = file_path.parent()
            file_dir.generate_dirs()
            file.data.to_file(file_path)

        json_path = output_dir.add("info.json")
        self.json.to_data().to_file(json_path)

    def get_name(self) -> str:
        return self.names["dat"][0]["val"]

    def load_pack_json(self) -> Optional["tbcml.JsonFile"]:
        pack_file = self.get_file_by_name("pack.json")
        if pack_file is None:
            return None
        return tbcml.JsonFile.from_data(pack_file.data)

    def load_units(self):
        units_data: list[Any] = self.pack_json["units"]["data"]
        units: list[BCUCat] = []
        for i, unit_data in enumerate(units_data):
            forms = unit_data["val"]["forms"]
            anims: list[list[BCUFile]] = []
            for form in forms:
                unit_id = form["anim"]["id"]
                anims.append(self.get_files_by_dir(unit_id))
            unit = BCUCat(
                unit_data,
                anims,
                i,
            )
            units.append(unit)
        return units

    def load_enemies(self):
        enemies_data: list[Any] = self.pack_json["enemies"]["data"]
        enemies: list[BCUEnemy] = []
        for i, enemy_data in enumerate(enemies_data):
            enemy_id = enemy_data["val"]["anim"]["id"]
            anims = self.get_files_by_dir(enemy_id)
            enemy = BCUEnemy(
                enemy_data["val"],
                BCUFileGroup(anims),
                i,
            )
            enemies.append(enemy)
        return enemies
