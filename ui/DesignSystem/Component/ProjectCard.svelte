<script lang="ts">
  import Badge from "../Component/Badge.svelte";
  import { BadgeType } from "../../src/badge";

  export let title: string;

  export let description = "";

  export let showMaintainerBadge: boolean = false;
</script>

<style>
  .project-card {
    display: flex;
    max-height: 3.2rem;
    flex-direction: column;
    justify-content: center;
    min-width: 0;
    margin-right: 1.5rem;
  }

  .title-row {
    display: flex;
    white-space: nowrap;
    width: -webkit-fill-available;
  }

  .title-row p {
    color: var(--color-foreground-level-6);
  }

  .desc {
    color: var(--color-foreground-level-6);
    margin-top: 0.125rem;
    width: -webkit-fill-available;
  }
</style>

<div class="project-card">
  <div class="title-row">
    <p class="typo-text-bold typo-overflow-ellipsis" {title}>{title}</p>
    {#if showMaintainerBadge}
      <Badge style="margin-left: 0.5rem" variant={BadgeType.Maintainer} />
    {/if}
  </div>
  {#if description.length > 0}
    <p class="desc typo-overflow-ellipsis" title={description}>{description}</p>
  {/if}
</div>
