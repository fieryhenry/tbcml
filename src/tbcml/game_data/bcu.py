from typing import Any, Optional
import tbcml


class InvalidBCUZipException(Exception):
    pass


class BCUForm:
    def __init__(
        self,
        form_data: dict[str, Any],
        anims: dict[str, "BCUFile"],
        cat_id: int,
        form: "tbcml.CatFormType",
    ):
        self.form_data = form_data
        self.anims = anims
        self.cat_id = cat_id
        self.form = form

    def get_anim(self) -> Optional["tbcml.Model"]:
        sprite = self.anims.get("sprite.png")
        imgcut = self.anims.get("imgcut.txt")
        mamodel = self.anims.get("mamodel.txt")
        if sprite is None or imgcut is None or mamodel is None:
            return None

        model = tbcml.Model()
        model.read_data(
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

    def get_display_icon(self) -> Optional["tbcml.BCImage"]:
        display_file = self.anims.get("icon_display.png")
        if display_file is None:
            return None

        return tbcml.BCImage.from_data(display_file.data)

    def get_deploy_icon(self) -> Optional["tbcml.BCImage"]:
        deploy_file = self.anims.get("icon_deploy.png")
        if deploy_file is None:
            return None

        return tbcml.BCImage.from_data(deploy_file.data)

    def write_to_cat_form(self, form: "tbcml.CatForm"):
        anim = self.get_anim()
        if anim is not None:
            form.anim = anim
            form.anim.mamodel.dup_ints()

        description = self.form_data.get("description", {}).get("dat", [])
        if len(description) > 0:
            description = description[0].get("val")
            if description is not None:
                form.description = str(description).split("<br>")

        name = self.form_data.get("names", {}).get("dat", [])
        if len(name) > 0:
            name = name[0].get("val")
            if name is not None:
                form.name = str(name)

        form.stats = self.to_stats()

        form.upgrade_icon = self.get_display_icon()
        form.deploy_icon = self.get_deploy_icon()
        form.format_bcu_upgrade_icon()
        form.format_bcu_deploy_icon()

        form.set_cat_id(self.cat_id)
        form.set_form(self.form, self.cat_id)

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
        stats.summon_id = BCUForm.get_proc_value(procs, "SPIRIT", "id", default=-1)
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
    def get_proc_value(
        procs: dict[str, dict[str, int]], proc_name: str, key: str, default: int = 0
    ):
        if proc_name in procs:
            return int(procs[proc_name][key])
        return default

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

    def get_cat_id_str(self):
        return tbcml.PaddedInt(self.cat_id, 3).to_str()

    def get_mamodel_name(self) -> str:
        return f"{self.get_cat_id_str()}_{self.form.value}.mamodel"

    def get_imgcut_name(self) -> str:
        return f"{self.get_cat_id_str()}_{self.form.value}.imgcut"

    def get_sprite_name(self) -> str:
        return f"{self.get_cat_id_str()}_{self.form.value}.png"

    def get_maanim_files(self) -> list["BCUFile"]:
        maanims: list["BCUFile"] = []
        for name, file in self.anims.items():
            if name.startswith("maanim"):
                maanims.append(file)
        return maanims

    def get_maanim_names(self) -> list[str]:
        maanims = self.get_maanim_files()
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
        maanims = self.get_maanim_files()
        maanim_data: list["tbcml.Data"] = []
        for maanim in maanims:
            maanim_id = tbcml.AnimType.from_bcu_str(maanim.name)
            if maanim_id is None:
                continue
            maanim_data.append(maanim.data)
        return maanim_data


class BCUCat:
    def __init__(
        self, unit_data: dict[str, Any], anims: list[dict[str, "BCUFile"]], cat_id: int
    ):
        self.unit_data = unit_data
        self.anims = anims

        forms: Optional[list[dict[str, Any]]] = self.unit_data.get("val", {}).get(
            "forms"
        )
        if forms is None:
            return

        self.forms: list[BCUForm] = []

        for i, (form_data, form_anims) in enumerate(zip(forms, anims)):
            self.forms.append(
                BCUForm(form_data, form_anims, cat_id, tbcml.CatFormType.from_index(i))
            )

    def get_val(self, val: str) -> Optional[Any]:
        return self.unit_data.get("val", {}).get(val)

    def write_to_cat(self, cat: "tbcml.Cat"):
        for i, form in enumerate(self.forms):
            form_real = cat.get_form(i)
            form.write_to_cat_form(form_real)

        unitbuy = cat.get_unitbuy()

        rarity = self.get_val("rarity")
        if rarity is not None:
            unitbuy.rarity = int(rarity)

        max_base = self.get_val("max")
        if max_base is not None:
            unitbuy.max_base_no_catseye = max_base
            unitbuy.max_base_catseye = max_base

        max_plus = self.get_val("maxp")
        if max_plus is not None:
            unitbuy.max_plus = max_plus

        unitbuy.set_obtainable(True)

        nypb = cat.get_nyanko_picture_book()
        nypb.is_displayed_in_cat_guide = True


class BCUEnemy:
    def __init__(
        self, enemy_data: dict[str, Any], anims: dict[str, "BCUFile"], enemy_id: int
    ):
        self.enemy_data = enemy_data
        self.anims = anims
        self.enemy_id = enemy_id

    def get_val(self, val: str) -> Optional[Any]:
        return self.enemy_data.get("val", {}).get(val)

    def get_enemy_id_str(self):
        return tbcml.PaddedInt(self.enemy_id, 3).to_str()

    def get_mamodel_name(self) -> str:
        return f"{self.get_enemy_id_str()}_e.mamodel"

    def get_imgcut_name(self) -> str:
        return f"{self.get_enemy_id_str()}_e.imgcut"

    def get_sprite_name(self) -> str:
        return f"{self.get_enemy_id_str()}_e.png"

    def get_maanim_files(self) -> list["BCUFile"]:
        maanims: list["BCUFile"] = []
        for name, file in self.anims.items():
            if name.startswith("maanim"):
                maanims.append(file)
        return maanims

    def get_maanim_names(self) -> list[str]:
        maanims = self.get_maanim_files()
        maanim_names: list[str] = []
        for maanim in maanims:
            maanim_id = tbcml.AnimType.from_bcu_str(maanim.name)
            if maanim_id is None:
                continue
            index_str = tbcml.PaddedInt(maanim_id.value, 2).to_str()
            maanim_names.append(f"{self.get_enemy_id_str()}_e{index_str}.maanim")
        return maanim_names

    def get_maanim_data(self) -> list["tbcml.Data"]:
        maanims = self.get_maanim_files()
        maanim_data: list["tbcml.Data"] = []
        for maanim in maanims:
            maanim_id = tbcml.AnimType.from_bcu_str(maanim.name)
            if maanim_id is None:
                continue
            maanim_data.append(maanim.data)
        return maanim_data

    def get_anim(self) -> Optional["tbcml.Model"]:
        sprite = self.anims.get("sprite.png")
        imgcut = self.anims.get("imgcut.txt")
        mamodel = self.anims.get("mamodel.txt")
        if sprite is None or imgcut is None or mamodel is None:
            return None

        model = tbcml.Model()
        model.read_data(
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

    def write_to_enemy(self, enemy: "tbcml.Enemy"):
        model = self.get_anim()
        if model is not None:
            enemy.anim = model

        enemy.stats = self.to_stats()

        description = self.enemy_data.get("description", {}).get("dat", [])
        if len(description) > 0:
            description = description[0].get("val")
            if description is not None:
                enemy.description = str(description).split("<br>")

        name = self.enemy_data.get("names", {}).get("dat", [])
        if len(name) > 0:
            name = name[0].get("val")
            if name is not None:
                enemy.name = str(name)

        enemy.set_enemy_id(enemy.enemy_id)

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
        stats.attack_interval = base_stats["tba"] // 2
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


class BCUFile:
    def __init__(
        self,
        file_info: dict[str, Any],
        enc_data: "tbcml.Data",
        cipher: "tbcml.AesCipher",
    ):
        path = file_info.get("path")
        if path is None:
            raise InvalidBCUZipException("BCU File has no path!")
        self.path = tbcml.Path(str(path).strip("./"))
        self.name = self.path.basename()

        size = file_info.get("size")
        if size is None:
            raise InvalidBCUZipException("BCU File has no size!")
        size = int(size)

        offset = file_info.get("offset")
        if offset is None:
            raise InvalidBCUZipException("BCU File has no offset!")
        offset = int(offset)

        padded_size = size + (16 - size % 16)

        enc_data = enc_data[offset : offset + padded_size]

        self.data = self.decrypt(enc_data, cipher, size)

    def decrypt(self, enc_data: "tbcml.Data", cipher: "tbcml.AesCipher", size: int):
        data = cipher.decrypt(enc_data)
        return data[:size]

    def extract(self, output_dir: "tbcml.Path"):
        file_path = output_dir.add(self.path)
        file_path.parent().generate_dirs()
        file_path.write(self.data)


class BCUZip:
    def __init__(self, enc_data: "tbcml.Data"):
        self.json, self.files = self.decrypt(enc_data)
        self.pack_json = self.get_pack_json()

    @staticmethod
    def from_file(path: "tbcml.PathStr"):
        path = tbcml.Path(path)
        return BCUZip(path.read())

    def get_key_iv(self, enc_data: "tbcml.Data"):
        if len(enc_data) < 0x20:
            raise InvalidBCUZipException("BCU Zip file is too small for header info!")
        iv_str = "battlecatsultimate"
        iv = tbcml.Hash(tbcml.HashAlgorithm.MD5).get_hash(tbcml.Data(iv_str))
        key = enc_data[0x10:0x20]
        return key, iv

    def decrypt(self, enc_data: "tbcml.Data"):
        if len(enc_data) < 0x24:
            raise InvalidBCUZipException("BCU Zip file is too small for header info!")

        json_length = enc_data[0x20:0x24].to_int_little()
        json_length_padded = 16 * (json_length // 16 + 1)

        length = 0x24 + json_length_padded

        if len(enc_data) < length:
            raise InvalidBCUZipException("BCU Zip file is too small for metadata data!")

        json_data_enc = enc_data[0x24:length]

        key, iv = self.get_key_iv(enc_data)

        aes = tbcml.AesCipher(key.to_bytes(), iv.to_bytes())

        json_data = aes.decrypt(json_data_enc)
        json_data = json_data[:json_length]  # remove padding

        enc_files_data = enc_data[length:]

        try:
            json_obj = tbcml.JsonFile.from_data(json_data)
        except UnicodeDecodeError:
            raise InvalidBCUZipException("BCU Zip could not be decrypted!")

        json: dict[str, Any] = json_obj.get_json()

        files_info = json.get("files") or []

        files: list[BCUFile] = []

        for file in files_info:
            files.append(BCUFile(file, enc_files_data, aes))

        return json_obj, files

    def get_file_by_name(self, name: str) -> Optional[BCUFile]:
        for file in self.files:
            if file.name == name:
                return file
        return None

    def get_pack_json(self) -> dict[str, Any]:
        pack_file = self.get_file_by_name("pack.json")
        if pack_file is None:
            raise InvalidBCUZipException("no pack.json was found!")
        return tbcml.JsonFile.from_data(pack_file.data).get_json()

    def get_bcu_cat(self, cat_id: int, bcu_index: int) -> Optional[BCUCat]:
        units_data: Optional[list[dict[str, Any]]] = self.pack_json.get(
            "units", {}
        ).get("data")
        if units_data is None:
            return
        for unit in units_data:
            if unit.get("val", {}).get("id", {}).get("id") != bcu_index:
                continue

            forms: Optional[list[dict[str, Any]]] = unit.get("val", {}).get("forms")
            if forms is None:
                continue

            anims: list[dict[str, BCUFile]] = []

            for form in forms:
                anim = form.get("anim", {})
                id = anim.get("id")
                base = anim.get("base")
                if id is None or base is None:
                    continue
                path = tbcml.Path(base).add(id)
                files = self.get_files_by_dir(path)
                anims.append(files)

            return BCUCat(unit, anims, cat_id)
        return None

    def get_bcu_enemy(self, enemy_id: int, bcu_index: int) -> Optional[BCUEnemy]:
        enemies_data: Optional[list[dict[str, Any]]] = self.pack_json.get(
            "enemies", {}
        ).get("data")
        if enemies_data is None:
            return

        for enemy in enemies_data:
            if enemy.get("val", {}).get("id", {}).get("id") != bcu_index:
                continue

            enemy = enemy.get("val")
            if enemy is None:
                continue

            anim = enemy.get("anim", {})
            id = anim.get("id")
            base = anim.get("base")
            if id is None or base is None:
                continue
            path = tbcml.Path(base).add(id)
            files = self.get_files_by_dir(path)

            return BCUEnemy(enemy, files, enemy_id)

        return None

    def get_files_by_dir(self, dir: "tbcml.Path") -> dict[str, BCUFile]:
        files: dict[str, BCUFile] = {}
        for file in self.files:
            if file.path.parent().to_str_forwards() == dir.to_str_forwards():
                files[file.name] = file
        return files

    def extract(self, output_dir: "tbcml.Path"):
        output_dir.generate_dirs()
        for file in self.files:
            file.extract(output_dir)

        json_path = output_dir.add("info.json")
        self.json.to_data().to_file(json_path)
