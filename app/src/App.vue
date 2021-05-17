<template>
  <Container :hasLogin="true" :isAdmin="true"></Container>
</template>

<script>
import Container from "./components/Container.vue";

export default {
    name: "App",
    components: {
        Container,
    },
};
</script>

<style>
</style>
