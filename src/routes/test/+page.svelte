<script lang="ts">
    import { commands } from "$lib/bindings";
    import Button from "$lib/components/ui/button/button.svelte";

    async function test(event: Event) {
        event.preventDefault();
        console.log("button clicked");
        let dbArgs = {
            encryption: 0,
            compression: 1,
            kdfVariant: 1,
            kdfIterations: 3,
            kdfMemoryKb: 65536,
            kdfThreads: 1,
        };
        await commands.newDb(dbArgs);

        const open = await commands.isDbOpen();
        if (open.status === "error" || open.data === false) {
            return false;
        }
        let args = {
            icon: "<svg/>",
            fields: {
                username: "user",
                password: "pass123",
            },
            url: "https://example.com",
            expiryUnix: null,
            expiryOffsetSecs: null,
            notes: "note",
        };
        commands.addEntry(args);
        const entries = await commands.listEntries();
        if (entries.status === "ok") {
            console.log(JSON.stringify(entries.data, null, 2));
        } else {
            console.log(JSON.stringify(entries.error, null, 2));
        }

        commands.saveDb({
            path: "/home/val/testDb.fedb",
            masterPassword: "test123 :3",
            atomic: true,
        });
        commands.closeDb();
    }
</script>

<main>
    <Button onclick={test}>Test</Button>
</main>
