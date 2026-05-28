#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>

#include "toxtunnel/app/known_servers.hpp"

using namespace toxtunnel::app;

namespace {

constexpr const char* kToxIdA =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
constexpr const char* kToxIdB =
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
constexpr const char* kToxIdLower =
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc1";

class KnownServersTest : public ::testing::Test {
   protected:
    void SetUp() override {
        const auto unique =
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        dir_ = std::filesystem::temp_directory_path() / ("toxtunnel_known_servers_test_" + unique);
        std::filesystem::create_directories(dir_);
    }
    void TearDown() override { std::filesystem::remove_all(dir_); }

    std::filesystem::path dir_;
};

}  // namespace

TEST_F(KnownServersTest, EmptyStoreOnFreshDir) {
    KnownServersStore store(dir_);
    EXPECT_TRUE(store.empty());
    EXPECT_EQ(store.size(), 0u);
    EXPECT_FALSE(store.last_load_error().has_value());
}

TEST_F(KnownServersTest, RejectsInvalidToxIdLength) {
    KnownServersStore store(dir_);
    KnownServer e;
    e.tox_id = "TOO_SHORT";
    EXPECT_FALSE(store.upsert(e));
    EXPECT_TRUE(store.empty());
}

TEST_F(KnownServersTest, UpsertAndFindByToxId) {
    KnownServersStore store(dir_);
    KnownServer e;
    e.tox_id = kToxIdA;
    e.alias = "alpha";
    EXPECT_TRUE(store.upsert(e));
    EXPECT_EQ(store.size(), 1u);

    auto hit = store.find_by_tox_id(kToxIdA);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->tox_id, kToxIdA);
    ASSERT_TRUE(hit->alias.has_value());
    EXPECT_EQ(*hit->alias, "alpha");
}

TEST_F(KnownServersTest, FindByAlias) {
    KnownServersStore store(dir_);
    KnownServer e;
    e.tox_id = kToxIdA;
    e.alias = "alpha";
    ASSERT_TRUE(store.upsert(e));

    auto by_alias = store.find_by_alias("alpha");
    ASSERT_TRUE(by_alias.has_value());
    EXPECT_EQ(by_alias->tox_id, kToxIdA);

    EXPECT_FALSE(store.find_by_alias("missing").has_value());
}

TEST_F(KnownServersTest, UpsertReplacesExistingByToxIdAndKeepsOneEntry) {
    KnownServersStore store(dir_);
    KnownServer e;
    e.tox_id = kToxIdA;
    e.alias = "alpha";
    ASSERT_TRUE(store.upsert(e));

    e.alias = "renamed";
    e.notes = "second pass";
    ASSERT_TRUE(store.upsert(e));

    EXPECT_EQ(store.size(), 1u);
    auto hit = store.find_by_tox_id(kToxIdA);
    ASSERT_TRUE(hit.has_value());
    ASSERT_TRUE(hit->alias.has_value());
    EXPECT_EQ(*hit->alias, "renamed");
    EXPECT_EQ(hit->notes, "second pass");
}

TEST_F(KnownServersTest, UpsertRejectsAliasCollisionWithDifferentToxId) {
    KnownServersStore store(dir_);
    KnownServer a;
    a.tox_id = kToxIdA;
    a.alias = "shared";
    ASSERT_TRUE(store.upsert(a));

    KnownServer b;
    b.tox_id = kToxIdB;
    b.alias = "shared";
    EXPECT_FALSE(store.upsert(b));
    EXPECT_EQ(store.size(), 1u);
}

TEST_F(KnownServersTest, ResolveAcceptsToxIdAndAliasAndUppercases) {
    KnownServersStore store(dir_);
    KnownServer a;
    a.tox_id = kToxIdA;
    a.alias = "alpha";
    ASSERT_TRUE(store.upsert(a));

    EXPECT_EQ(store.resolve_tox_id(kToxIdA), kToxIdA);
    EXPECT_EQ(store.resolve_tox_id("alpha"), kToxIdA);
    // Lower-case input should be uppercased on resolve.
    EXPECT_EQ(store.resolve_tox_id(kToxIdLower).size(), 76u);
    EXPECT_EQ(store.resolve_tox_id(kToxIdLower).front(), 'C');
    // Unknown alias falls through unchanged so the caller gets a clear error.
    EXPECT_EQ(store.resolve_tox_id("ghost"), "ghost");
}

TEST_F(KnownServersTest, RecordConnectionInsertsAndRefreshes) {
    KnownServersStore store(dir_);
    EXPECT_TRUE(store.record_connection(kToxIdA, KnownConnectionType::Udp));
    auto hit = store.find_by_tox_id(kToxIdA);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->last_connection_type, KnownConnectionType::Udp);
    EXPECT_TRUE(hit->first_connected_at.has_value());
    EXPECT_TRUE(hit->last_connected_at.has_value());
    const auto first = *hit->first_connected_at;

    // Subsequent record keeps first_connected_at, updates last_connection_type.
    EXPECT_TRUE(store.record_connection(kToxIdA, KnownConnectionType::Tcp));
    hit = store.find_by_tox_id(kToxIdA);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit->first_connected_at, first);
    EXPECT_EQ(hit->last_connection_type, KnownConnectionType::Tcp);
}

TEST_F(KnownServersTest, RecordInfoUpsertsOrUpdates) {
    KnownServersStore store(dir_);
    KnownServerInfo info;
    info.hostname = "nas-01";
    info.os = "Linux";
    EXPECT_TRUE(store.record_info(kToxIdA, info));
    auto hit = store.find_by_tox_id(kToxIdA);
    ASSERT_TRUE(hit.has_value());
    ASSERT_TRUE(hit->info.hostname.has_value());
    EXPECT_EQ(*hit->info.hostname, "nas-01");
    EXPECT_TRUE(hit->info.reported_at.has_value());
}

TEST_F(KnownServersTest, UpsertReplacesWholesaleByDesign) {
    // Pins the documented behavior of `upsert`: passing a partially-populated
    // KnownServer wipes any unset fields. The CLI `servers add` command guards
    // against this by reading the existing record first (regression: P2#3).
    KnownServersStore store(dir_);
    KnownServer rich;
    rich.tox_id = kToxIdA;
    rich.alias = "alpha";
    rich.first_connected_at = "2026-05-01T00:00:00Z";
    rich.last_connected_at = "2026-05-13T00:00:00Z";
    rich.last_connection_type = KnownConnectionType::Udp;
    rich.info.hostname = "nas-01";
    rich.notes = "rich notes";
    ASSERT_TRUE(store.upsert(rich));

    KnownServer thin;
    thin.tox_id = kToxIdA;
    thin.alias = "renamed";
    ASSERT_TRUE(store.upsert(thin));

    auto hit = store.find_by_tox_id(kToxIdA);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(*hit->alias, "renamed");
    EXPECT_FALSE(hit->first_connected_at.has_value());
    EXPECT_FALSE(hit->last_connected_at.has_value());
    EXPECT_EQ(hit->last_connection_type, KnownConnectionType::None);
    EXPECT_FALSE(hit->info.hostname.has_value());
    EXPECT_EQ(hit->notes, "");
}

TEST_F(KnownServersTest, RemoveByAliasOrToxId) {
    KnownServersStore store(dir_);
    KnownServer a;
    a.tox_id = kToxIdA;
    a.alias = "alpha";
    ASSERT_TRUE(store.upsert(a));
    KnownServer b;
    b.tox_id = kToxIdB;
    ASSERT_TRUE(store.upsert(b));
    EXPECT_EQ(store.size(), 2u);

    EXPECT_TRUE(store.remove("alpha"));
    EXPECT_FALSE(store.remove("alpha"));  // already gone
    EXPECT_TRUE(store.remove(kToxIdB));
    EXPECT_TRUE(store.empty());
}

TEST_F(KnownServersTest, RoundTripPersistsAllFields) {
    {
        KnownServersStore store(dir_);
        KnownServer a;
        a.tox_id = kToxIdA;
        a.alias = "alpha";
        a.first_connected_at = "2026-05-13T03:00:00Z";
        a.last_connected_at = "2026-05-13T03:14:22Z";
        a.last_connection_type = KnownConnectionType::Udp;
        a.info.hostname = "nas-01";
        a.info.os = "Linux";
        a.info.os_version = "6.6.0";
        a.info.arch = "aarch64";
        a.info.uptime_seconds = 84221;
        a.info.toxtunnel_version = "0.1.11";
        a.info.reported_at = "2026-05-13T03:14:22Z";
        a.notes = "homelab nas";
        ASSERT_TRUE(store.upsert(a));
        ASSERT_TRUE(store.save().has_value());
    }

    KnownServersStore store(dir_);
    EXPECT_FALSE(store.last_load_error().has_value());
    ASSERT_EQ(store.size(), 1u);
    auto hit = store.find_by_alias("alpha");
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->tox_id, kToxIdA);
    EXPECT_EQ(hit->last_connection_type, KnownConnectionType::Udp);
    ASSERT_TRUE(hit->info.hostname.has_value());
    EXPECT_EQ(*hit->info.hostname, "nas-01");
    EXPECT_EQ(*hit->info.uptime_seconds, 84221u);
    EXPECT_EQ(hit->notes, "homelab nas");
}

TEST_F(KnownServersTest, MalformedFileSurfacesViaLastLoadError) {
    auto path = dir_ / "known_servers.yaml";
    {
        std::ofstream ofs(path);
        ofs << "this: is: not: valid: yaml\n  - because: of\n: extra colons\n";
    }
    KnownServersStore store(dir_);
    EXPECT_TRUE(store.empty());
    EXPECT_TRUE(store.last_load_error().has_value());
}

TEST_F(KnownServersTest, EntriesAreSortedAliasFirstThenToxId) {
    KnownServersStore store(dir_);
    KnownServer a;
    a.tox_id = kToxIdA;
    KnownServer b;
    b.tox_id = kToxIdB;
    b.alias = "beta";
    KnownServer c;
    c.tox_id = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    c.alias = "alpha";
    ASSERT_TRUE(store.upsert(a));
    ASSERT_TRUE(store.upsert(b));
    ASSERT_TRUE(store.upsert(c));

    auto entries = store.entries();
    ASSERT_EQ(entries.size(), 3u);
    EXPECT_EQ(*entries[0].alias, "alpha");
    EXPECT_EQ(*entries[1].alias, "beta");
    EXPECT_FALSE(entries[2].alias.has_value());
}
