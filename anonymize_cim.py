
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Обезличивание CIM RDF/XML.

Запуск:
    pip install lxml
    python anonymize_cim.py input.xml output.xml

Дополнительно:
    python anonymize_cim.py input.xml output.xml --config config.json
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from lxml import etree


RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"

RDF_ABOUT = f"{{{RDF_NS}}}about"
RDF_ID = f"{{{RDF_NS}}}ID"
RDF_RESOURCE = f"{{{RDF_NS}}}resource"


DEFAULT_CONFIG = {
    "anonymize_coordinates": True,
    "replace_all_name_fields": True,
    "external_url_policy": "only_object_urls",

    "fruit_names": [
        "Абрикосовый", "Грушевый", "Сливовый",
        "Персиковый", "Яблочный", "Вишнёвый",
        "Черешневый", "Айвовый", "Лимонный",
        "Мандариновый", "Черничный", "Брусничный"
    ],

    "first_names": [
        "Александр", "Михаил", "Иван", "Дмитрий",
        "Анна", "Мария", "Елена", "Ольга"
    ],

    "last_names": [
        "Смирнов", "Кузнецов", "Попов",
        "Васильев", "Петров", "Соколов"
    ],

    "middle_names": [
        "Александрович", "Михайлович",
        "Иванович", "Дмитриевич",
        "Александровна", "Михайловна",
        "Ивановна", "Дмитриевна"
    ],

    "organization_suffixes": [
        "Энерго", "Сервис", "Сеть", "Тех", "Ресурс"
    ],

    "email_domain": "example.invalid",

    "person_tag_hints": [
        "fio", "surname", "firstname", "lastname",
        "middlename", "personname", "contactname"
    ],

    "phone_tag_hints": [
        "phone", "telephone", "mobile", "fax"
    ],

    "email_tag_hints": [
        "email", "e-mail", "mail"
    ],

    "address_tag_hints": [
        "address", "street", "postaladdress"
    ],

    "numeric_tag_hints": [
        "inn", "kpp", "snils", "passport",
        "personnelnumber", "tabel"
    ],

    "coordinate_tag_hints": [
        "latitude", "longitude", "coordinates"
    ],

    "free_text_tag_hints": [
        "comment", "remark", "note",
        "annotation", "log", "message"
    ],

    "preserve_tag_hints": [
        "voltage", "rated", "length",
        "resistance", "reactance", "capacitance",
        "current", "power", "frequency",
        "cabletype", "wiretype", "conductor",
        "manufacturer", "model", "phase",
        "sequence", "multiplier", "unit",
        "type", "class"
    ]
}


def local_name(tag):
    return tag.rsplit("}", 1)[-1].lower()


def digest(secret, category, value):
    return hmac.new(
        secret,
        (category + "\0" + value).encode("utf-8"),
        hashlib.sha256
    ).digest()


def stable_index(secret, category, value, count):
    return int.from_bytes(
        digest(secret, category, value)[:8],
        "big"
    ) % count


def load_config(path):
    config = DEFAULT_CONFIG.copy()

    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as file:
            custom = json.load(file)
        config.update(custom)

    return config


def get_secret(path):
    key_path = Path(path)

    if key_path.exists():
        secret = key_path.read_bytes()

        if len(secret) < 16:
            raise ValueError("Файл секретного ключа слишком короткий.")

        return secret

    secret = secrets.token_bytes(32)
    key_path.write_bytes(secret)

    print(
        f"[INFO] Создан ключ {path}. "
        "Сохраните его отдельно."
    )

    return secret


class Anonymizer:

    def __init__(self, config, secret, db_path):
        self.cfg = config
        self.secret = secret

        self.db = sqlite3.connect(db_path)

        self.db.execute("""
            CREATE TABLE IF NOT EXISTS mapping (
                category TEXT NOT NULL,
                original TEXT NOT NULL,
                replacement TEXT NOT NULL,
                PRIMARY KEY(category, original),
                UNIQUE(category, replacement)
            )
        """)

        self.db.commit()

    def close(self):
        self.db.commit()
        self.db.close()

    def get(self, category, original, maker):

        if not original:
            return original

        row = self.db.execute(
            """
            SELECT replacement
            FROM mapping
            WHERE category = ? AND original = ?
            """,
            (category, original)
        ).fetchone()

        if row:
            return row[0]

        replacement = maker(original)
        base = replacement
        counter = 0

        while self.db.execute(
            """
            SELECT 1 FROM mapping
            WHERE category = ? AND replacement = ?
            """,
            (category, replacement)
        ).fetchone():

            counter += 1
            replacement = f"{base}_{counter}"

        self.db.execute(
            "INSERT INTO mapping VALUES (?, ?, ?)",
            (category, original, replacement)
        )

        return replacement

    def synthetic_person(self, value):

        first = self.cfg["first_names"]
        last = self.cfg["last_names"]
        middle = self.cfg["middle_names"]

        d = digest(self.secret, "person", value)

        return (
            f"{last[d[0] % len(last)]} "
            f"{first[d[1] % len(first)]} "
            f"{middle[d[2] % len(middle)]}"
        )

    def synthetic_fruit(self, value):

        fruits = self.cfg["fruit_names"]

        index = stable_index(
            self.secret, "object", value, len(fruits)
        )

        return fruits[index] + " объект"

    def numeric(self, value, category):

        digits = re.sub(r"\D", "", value)

        if not digits:
            return value

        d = digest(self.secret, category, value)

        generated = ""

        while len(generated) < len(digits):
            generated += "".join(str(x % 10) for x in d)
            d = hashlib.sha256(d).digest()

        iterator = iter(generated[:len(digits)])

        return "".join(
            next(iterator) if char.isdigit() else char
            for char in value
        )

    def anonymize_uri(self, value):

        if value.startswith("#"):
            original = value[1:]

            replacement = self.get(
                "rdf-id",
                original,
                lambda x: "obj_" + digest(
                    self.secret, "rdf-id", x
                ).hex()[:20]
            )

            return "#" + replacement

        if "://" not in value:
            return self.get(
                "rdf-id",
                value,
                lambda x: "obj_" + digest(
                    self.secret, "rdf-id", x
                ).hex()[:20]
            )

        if self.cfg.get("external_url_policy") != "all":
            return value

        parts = urlsplit(value)

        tail = parts.path.rstrip("/").split("/")[-1]

        replacement = self.get(
            "url-id",
            tail,
            lambda x: "resource-" + digest(
                self.secret, "url", x
            ).hex()[:16]
        )

        new_path = (
            parts.path.rstrip("/").rsplit("/", 1)[0]
            + "/"
            + replacement
        )

        return urlunsplit((
            parts.scheme,
            parts.netloc,
            new_path,
            parts.query,
            parts.fragment
        ))

    def classify(self, tag):

        name = local_name(tag)

        # Технические характеристики сохраняются.
        if any(
            hint in name
            for hint in self.cfg["preserve_tag_hints"]
        ):
            return None

        if any(
            hint in name
            for hint in self.cfg["coordinate_tag_hints"]
        ):
            return (
                "coordinate"
                if self.cfg["anonymize_coordinates"]
                else None
            )

        if any(h in name for h in self.cfg["phone_tag_hints"]):
            return "phone"

        if any(h in name for h in self.cfg["email_tag_hints"]):
            return "email"

        if any(h in name for h in self.cfg["address_tag_hints"]):
            return "address"

        if any(h in name for h in self.cfg["numeric_tag_hints"]):
            return "numeric"

        if any(h in name for h in self.cfg["person_tag_hints"]):
            return "person"

        if any(h in name for h in self.cfg["free_text_tag_hints"]):
            return "free"

        if "name" in name and self.cfg["replace_all_name_fields"]:
            return "object-name"

        return None

    def transform(self, tag, value):

        if value is None or not value.strip():
            return value

        kind = self.classify(tag)

        if kind == "person":
            return self.get(
                "person", value, self.synthetic_person
            )

        if kind == "object-name":
            return self.get(
                "object-name", value, self.synthetic_fruit
            )

        if kind == "numeric":
            return self.get(
                "numeric",
                value,
                lambda x: self.numeric(x, "numeric")
            )

        if kind == "phone":
            return self.get(
                "phone",
                value,
                lambda x: self.numeric(x, "phone")
            )

        if kind == "coordinate":
            return self.get(
                "coordinate",
                value,
                lambda x: self.numeric(x, "coordinate")
            )

        if kind == "email":

            def make_email(original):
                local = digest(
                    self.secret, "email", original
                ).hex()[:12]

                return f"user-{local}@{self.cfg['email_domain']}"

            return self.get("email", value, make_email)

        if kind == "address":

            def make_address(original):
                index = stable_index(
                    self.secret,
                    "street",
                    original,
                    len(self.cfg["fruit_names"])
                )

                number = 1 + stable_index(
                    self.secret, "house", original, 200
                )

                return (
                    f"ул. {self.cfg['fruit_names'][index]}, "
                    f"д. {number}"
                )

            return self.get("address", value, make_address)

        if kind == "free":
            return self.mask_free_text(value)

        return value

    def mask_free_text(self, value):

        result = value

        result = re.sub(
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            lambda m: self.transform("email", m.group(0)),
            result,
            flags=re.I
        )

        result = re.sub(
            r"(?<!\w)(?:\+?\d[\d ()-]{8,}\d)(?!\w)",
            lambda m: self.numeric(m.group(0), "free-phone"),
            result
        )

        rows = self.db.execute(
            """
            SELECT original, replacement
            FROM mapping
            WHERE category = 'object-name'
            """
        ).fetchall()

        for old, new in sorted(
            rows, key=lambda item: len(item[0]), reverse=True
        ):
            if old:
                result = result.replace(old, new)

        return result


def first_pass(input_path, anonymizer):

    print("[1/4] Анализ XML...")

    for _, elem in etree.iterparse(
        input_path,
        events=("end",),
        resolve_entities=False,
        no_network=True,
        huge_tree=True
    ):

        for attr in (RDF_ABOUT, RDF_ID):

            value = elem.get(attr)

            if value:
                anonymizer.anonymize_uri(value)

        for child in elem:

            if child.text and child.text.strip():
                if "name" in local_name(child.tag):
                    anonymizer.get(
                        "object-name",
                        child.text,
                        anonymizer.synthetic_fruit
                    )

        elem.clear()

        parent = elem.getparent()

        if parent is not None:
            while elem.getprevious() is not None:
                del parent[0]

    anonymizer.db.commit()


def rewrite_tree(elem, anonymizer):

    # Изменяем идентификаторы и ссылки.
    for attr_name, attr_value in list(elem.attrib.items()):

        if attr_name in (RDF_ABOUT, RDF_ID, RDF_RESOURCE):
            elem.set(
                attr_name,
                anonymizer.anonymize_uri(attr_value)
            )

        else:
            replacement = anonymizer.transform(
                attr_name, attr_value
            )

            if replacement != attr_value:
                elem.set(attr_name, replacement)

    # Изменяем текст XML-элемента.
    if elem.text and elem.text.strip():
        elem.text = anonymizer.transform(
            elem.tag, elem.text
        )

    # Рекурсивно обрабатываем дочерние элементы.
    for child in elem:
        rewrite_tree(child, anonymizer)

        if child.tail and child.tail.strip():
            if any(
                hint in local_name(elem.tag)
                for hint in anonymizer.cfg["free_text_tag_hints"]
            ):
                child.tail = anonymizer.mask_free_text(
                    child.tail
                )


def second_pass(input_path, output_path, anonymizer):

    print("[2/4] Обезличивание XML...")

    context = etree.iterparse(
        input_path,
        events=("start", "end"),
        resolve_entities=False,
        no_network=True,
        huge_tree=True
    )

    root_tag = None
    root_attributes = None
    root_nsmap = None
    depth = 0

    with etree.xmlfile(output_path, encoding="UTF-8") as writer:

        writer.write_declaration()

        for event, elem in context:

            if event == "start":
                depth += 1

                if depth == 1:
                    root_tag = elem.tag
                    root_attributes = dict(elem.attrib)
                    root_nsmap = elem.nsmap

                    root_element = writer.element(
                        root_tag,
                        attrib=root_attributes,
                        nsmap=root_nsmap
                    )

                    root_element.__enter__()

                continue

            if depth == 2:
                rewrite_tree(elem, anonymizer)

                writer.write(elem)

                elem.clear()

                parent = elem.getparent()

                if parent is not None:
                    while elem.getprevious() is not None:
                        del parent[0]

            depth -= 1

        if depth != 0:
            raise ValueError("Некорректная структура XML.")

        if root_tag is None:
            raise ValueError("XML-файл пуст.")

        root_element.__exit__(None, None, None)


def validate_xml(path):

    print("[3/4] Проверка результата...")

    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        huge_tree=True
    )

    try:
        etree.parse(path, parser)

    except etree.XMLSyntaxError as error:
        raise ValueError(
            f"Ошибка структуры итогового XML: {error}"
        )


def main():

    parser = argparse.ArgumentParser(
        description="Обезличивание CIM RDF/XML"
    )

    parser.add_argument("input_xml")
    parser.add_argument("output_xml")

    parser.add_argument(
        "--config",
        default="config.json"
    )

    parser.add_argument(
        "--key",
        default="secret.key"
    )

    parser.add_argument(
        "--db",
        default="anonymization_map.sqlite"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.input_xml):
        parser.error(
            f"Файл не найден: {args.input_xml}"
        )

    if os.path.abspath(args.input_xml) == os.path.abspath(args.output_xml):
        parser.error("Входной и выходной файлы должны различаться.")

    config = load_config(args.config)
    secret = get_secret(args.key)

    anonymizer = Anonymizer(
        config,
        secret,
        args.db
    )

    try:

        first_pass(args.input_xml, anonymizer)

        print("[2/4] Запись обезличенной модели...")

        second_pass(
            args.input_xml,
            args.output_xml,
            anonymizer
        )

        validate_xml(args.output_xml)

        print("[4/4] Обезличивание завершено.")
        print(f"Результат: {args.output_xml}")
        print(f"Ключ: {args.key}")
        print(f"База соответствий: {args.db}")

    finally:
        anonymizer.close()


if __name__ == "__main__":
    main()
