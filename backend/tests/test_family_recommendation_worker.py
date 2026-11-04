import unittest

from workers.celery_app import celery_app


class FamilyRecommendationWorkerTest(unittest.TestCase):
    def test_family_queue_has_independent_route(self):
        queue = celery_app.amqp.queues["queue_family"]

        self.assertEqual(queue.exchange.name, "queue_family")
        self.assertEqual(queue.routing_key, "queue_family")


if __name__ == "__main__":
    unittest.main()
