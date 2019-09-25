#pragma once

#include <types.h>

/* The ACPI Root System Description Pointer (RSDP). */
struct rsdp {
	char     signature[8];
	uint8_t  checksum;
	char     oem_id[6];
	uint8_t  revision;
	uint32_t rsdt_base;
} __attribute__ ((packed));

struct rsdp20 {
	struct rsdp rsdp;
	uint32_t    len;
	uint64_t    xsdt_base;
	uint8_t     checksum;
	uint8_t     reserved[3];
} __attribute__ ((packed));

struct acpi_hdr {
	char     signature[4];
	uint32_t len;
	uint8_t  revision;
	uint8_t  checksum;
	char     oem_id[6];
	char     oem_table_id[8];
	uint32_t oem_revision;
	uint32_t creator_id;
	uint32_t creator_revision;
} __attribute__ ((packed));

/* The ACPI Multiple APIC Description Table (MADT) */
struct madt {
	struct acpi_hdr hdr;
	uint32_t        lapic_base;
	uint32_t        flags;
} __attribute__ ((packed));

struct madt_lapic {
	uint8_t  cpu_id;
	uint8_t  apic_id;
	uint32_t flags;
} __attribute__ ((packed));

struct madt_ioapic {
	uint8_t  apic_id;
	uint8_t  reserved;
	uint32_t ioapic_base;
	uint32_t gsi_base;
} __attribute__ ((packed));

struct madt_iso {
	uint8_t  bus_src;
	uint8_t  irq_src;
	uint32_t gsi;
	uint16_t flags;
} __attribute__ ((packed));

struct madt_nmi {
	uint8_t  cpu_id;
	uint16_t flags;
	uint8_t  lint;
} __attribute__ ((packed));

struct madt_lapic64 {
	uint16_t reserved;
	uint64_t lapic_base;
} __attribute__ ((packed));

struct madt_entry {
	uint8_t type;
	uint8_t len;
	union {
		struct madt_lapic   lapic;
		struct madt_ioapic  ioapic;
		struct madt_iso     iso;
		struct madt_nmi     nmi;
		struct madt_lapic64 lapic64;
	};
} __attribute__ ((packed));

enum {
	MADT_LAPIC = 0,
	MADT_IOAPIC,
	MADT_ISO,
	MADT_NMI,
	MADT_LAPIC64,
};

