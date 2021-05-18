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
body {
  background-color: #f5f5f5;
}
</style>
